package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

/*
https://man7.org/linux/man-pages/man7/netlink.7.html
https://man7.org/linux/man-pages/man7/sock_diag.7.html
*/

const SOCK_DIAG_BY_FAMILY = 20
const pathProc = "/proc"

type inetDiagSockid struct {
	idiagSport  [2]byte   //__be16  idiag_sport;
	idiagDport  [2]byte   //__be16  idiag_dport;
	idiagSrc    [16]byte  //__be32  idiag_src[4];
	idiagDst    [16]byte  //__be32  idiag_dst[4];
	idiagIf     uint32    //uint32   idiag_if;
	idiagCookie [2]uint32 //uint32   idiag_cookie[2];
}

type inetDiagReqV2 struct {
	sdiagFamily   uint8
	sdiagProtocol uint8
	idiag_ext     uint8
	pad           uint8
	udiagStates   uint32
	id            inetDiagSockid
}

type InetDiagMsg struct {
	idiagFamily  uint8
	idiagState   uint8
	idiagTimer   uint8
	idiagRetrans uint8
	id           inetDiagSockid
	idiagExpires uint32
	idiagRqueue  uint32
	idiagWqueue  uint32
	idiagUid     uint32
	idiagInode   uint32
}

func packInetDiagReq(protocol uint8, sourceAddr net.IP, sourcePort int) (data []byte) {
	type Req struct {
		nlh syscall.NlMsghdr
		udr inetDiagReqV2
	}
	var family uint8
	var src [16]byte
	var sport [2]byte
	if v4 := sourceAddr.To4(); v4 != nil {
		family = syscall.AF_INET
		copy(src[:], v4)
	} else {
		family = syscall.AF_INET6
		copy(src[:], sourceAddr)
	}
	binary.BigEndian.PutUint16(sport[:], uint16(sourcePort))
	req := Req{
		nlh: syscall.NlMsghdr{
			Len:   uint32(unsafe.Sizeof(Req{})),
			Type:  SOCK_DIAG_BY_FAMILY,
			Flags: syscall.NLM_F_REQUEST | syscall.NLM_F_DUMP,
			Seq:   1,
			Pid:   0,
		},
		udr: inetDiagReqV2{
			sdiagFamily:   family,
			sdiagProtocol: protocol,
			idiag_ext:     0,
			pad:           0,
			udiagStates:   math.MaxUint32,
			id: inetDiagSockid{
				idiagSport:  sport,
				idiagDport:  [2]byte{},
				idiagSrc:    src,
				idiagDst:    [16]byte{},
				idiagIf:     0,
				idiagCookie: [2]uint32{math.MaxUint32, math.MaxUint32},
			},
		},
	}
	return (*(*[unsafe.Sizeof(req)]byte)(unsafe.Pointer(&req)))[:]

}

func ParseInetDiagResp(data []byte) (msg *InetDiagMsg, err error) {
	if expectedLength := int(unsafe.Sizeof(InetDiagMsg{})); len(data) < expectedLength {
		return nil, fmt.Errorf("wrong data length to parse dial response: %v and expect %v", len(data), expectedLength)
	}
	var d [unsafe.Sizeof(InetDiagMsg{})]byte
	copy(d[:], data[:])
	return (*InetDiagMsg)(unsafe.Pointer(&d)), nil
}

func GetInformationFromNetlink(network string, sourceIP net.IP, sourcePort int) (msg *InetDiagMsg, err error) {
	socket, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_DGRAM, syscall.NETLINK_INET_DIAG)
	if err != nil {
		return nil, fmt.Errorf("cannot setup inet diag socket: %v", err)
	}
	err = syscall.Connect(socket, &syscall.SockaddrNetlink{
		Family: syscall.AF_NETLINK,
		Pad:    0,
		Pid:    0,
		Groups: 0,
	})
	if err != nil {
		return nil, fmt.Errorf("fail to connect: %v", err)
	}
	var protocol uint8
	switch strings.ToLower(network) {
	case "tcp":
		protocol = syscall.IPPROTO_TCP
	case "udp":
		protocol = syscall.IPPROTO_UDP
	default:
		return nil, fmt.Errorf("unsupported netowrk: %v", network)
	}
	req := packInetDiagReq(protocol, sourceIP, sourcePort)
	_, err = syscall.Write(socket, req)
	if err != nil {
		return nil, fmt.Errorf("error occurs when write inet diag request: %v", err)
	}
	var resp [2048]byte
	n, err := syscall.Read(socket, resp[:])
	if err != nil {
		return nil, fmt.Errorf("error occurs when read inet diag response: %v", err)
	}
	nlmsg, err := syscall.ParseNetlinkMessage(resp[:n])
	if len(nlmsg) == 0 {
		err = io.EOF
	}
	if err != nil {
		return nil, fmt.Errorf("error occurs when ParseNetlinkMessage: %v", err)
	}
	diagMsg, err := ParseInetDiagResp(nlmsg[0].Data)
	if err != nil {
		return nil, fmt.Errorf("error occurs when parse inet diag response: %v", err)
	}
	return diagMsg, err
}

func GetProcessNameByInode(inode, uid uint32) (string, error) {
	f, err := ioutil.ReadDir(pathProc)
	if err != nil {
		return "", fmt.Errorf("cannot open the directory /proc: %v", err)
	}
	var pid string
	var found bool
loop1:
	for _, fi := range f {
		pid = fi.Name()
		if !fi.IsDir() {
			continue
		}
		if fi.Sys().(*syscall.Stat_t).Uid != uid {
			continue
		}
		for _, t := range pid {
			if t > '9' || t < '0' {
				continue loop1
			}
		}
		if is := isProcessInode(pid, strconv.Itoa(int(inode))); is {
			found = true
			break
		}
	}
	if !found {
		return "", nil
	}
	return getProcessName(pid), nil
}

func getProcessName(pid string) (pn string) {
	p := filepath.Join(pathProc, pid, "stat")
	b, err := ioutil.ReadFile(p)
	if err != nil {
		return
	}
	sp := bytes.SplitN(b, []byte(" "), 3)
	pn = string(sp[1])
	return resolveProcName(pn)
}
func resolveProcName(s string) string {
	i := strings.Index(s, "(")
	if i < 0 {
		return ""
	}
	s = s[i+1:]
	j := strings.LastIndex(s, ")")
	if j < 0 {
		return ""
	}
	return s[:j]
}

func isProcessInode(pid, inode string) bool {
	// link name is of the form socket:[5860846]
	p := filepath.Join(pathProc, pid, "fd")
	f, err := os.Open(p)
	fns, err := f.Readdirnames(-1)
	f.Close()
	if err != nil {
		return false
	}
	for _, fn := range fns {
		lk, err := os.Readlink(filepath.Join(p, fn))
		if err != nil {
			continue
		}
		target := "socket:[" + inode + "]"
		if lk == target {
			return true
		}
	}
	return false
}

func main() {
	l, err := net.ListenTCP("tcp", &net.TCPAddr{
		Port: 11111,
	})

	if err != nil {
		log.Fatalf("listen error: %v", err.Error())
	}

	for {
		fd, err := l.Accept()
		if err != nil {
			log.Fatalf("accept error: %v", err.Error())
		}
		// only support linux now
		if runtime.GOOS == "linux" {
			host, port, err := net.SplitHostPort(fd.RemoteAddr().String())
			if err != nil {
				log.Fatalf("splitHostPort failed: %v", err)
			}
			src := net.ParseIP(host)
			sport, err := strconv.Atoi(port)
			if err != nil {
				log.Fatalf("failed to convert port to int: %v", err)
			}
			msg, err := GetInformationFromNetlink("tcp", src, sport)
			if err != nil {
				log.Fatalf("failed to GetInformationFromNetlink: %v", err)
			}
			pname, _ := GetProcessNameByInode(msg.idiagInode, msg.idiagUid)
			fmt.Printf("addr: %s\n", fd.RemoteAddr().String())
			fmt.Printf("uid: %d\n", msg.idiagUid)
			fmt.Printf("inode: %d\n", msg.idiagInode)
			fmt.Printf("pname: %s\n", pname)
		}
	}
}
