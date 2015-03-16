package main

import (
	"./fixedhistory"
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/ActiveState/tail"
	"github.com/cenkalti/rpc2"
	"io/ioutil"
	"net"
	"os"
	"regexp"
	"strings"
	"time"
)

type PrivMsg struct {
	Target, Text string
}

type HistoryItem struct {
	v string
	t *time.Time
}

func init() {
	var err error
	config, err = NewConfig("./logcat.json")
	if err != nil {
		panic(err)
	}

	history = fixedhistory.NewHistory(config.MaxItems)
	history.ValueMap = func(i interface{}) interface{} {
		switch t := i.(type) {
		case *HistoryItem:
			return t.v
		}
		return i
	}
	// define cleanup
	go func() {
		interval := time.NewTicker(time.Duration(config.Interval) * time.Minute)
		for {
			history.Cleanup(func(i interface{}) bool {
				switch t := i.(type) {
				case *HistoryItem:
					return time.Since(*t.t) > time.Duration(config.Interval)*time.Minute
				}
				return false
			})
			<-interval.C
		}
	}()

	f, err := os.Open("/usr/share/nmap/nmap-services")
	if err == nil {
		services = make(map[string]string)
		re_service := regexp.MustCompile("^(.+?)\\s+([0-9]+/[a-z]+)")
		data_lines := bufio.NewScanner(f)
		for data_lines.Scan() {
			line := data_lines.Text()
			if match := re_service.FindStringSubmatch(line); len(match) > 0 {
				services[match[2]] = match[1]
			}
		}
	}
}

type Config struct {
	Channels []string `json:"channels"`
	Logfile  string   `json:"logfile"`
	MaxItems int      `json:"max_items"`
	Interval int      `json:"cleanup_interval"`
}

func NewConfig(path string) (*Config, error) {
	config := &Config{}
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(data, config)
	return config, err
}

var history *fixedhistory.FixedArray
var services map[string]string
var config *Config
var debug bool

func main() {
	flag.BoolVar(&debug, "debug", false, "debug mode")
	flag.Parse()

	var reply bool
	var c *rpc2.Client

	if debug == false {
		conn, err := net.Dial("tcp", "localhost:1234")
		if err != nil {
			panic(err)
		}
		c = rpc2.NewClient(conn)
		go func() {
			for {
				c.Run()
			}
		}()

		c.Call("register", struct{}{}, &reply)

		for _, channel := range config.Channels {
			c.Call("join", channel, &reply)
		}
	}

	go func() {
		iptables := regexp.MustCompile("badguy dropped: .*SRC=([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}) .* PROTO=([A-Z]+)(?: .* DPT=([0-9]{1,5}))?")
		fi, err := os.Stat(config.Logfile)
		if err != nil {
			fmt.Println("ERR:", err)
			return
		}

		log, err := tail.TailFile(config.Logfile, tail.Config{
			Follow:   true,
			ReOpen:   true,
			Logger:   tail.DiscardingLogger,
			Location: &tail.SeekInfo{fi.Size(), 0},
		})
		if err != nil {
			fmt.Println("ERR:", err)
			return
		}
		for line := range log.Lines {
			if match := iptables.FindStringSubmatch(line.Text); len(match) > 0 {
				service, ok := services[fmt.Sprintf("%v/%v", match[3], strings.ToLower(match[2]))]
				suffix := ""
				var msg string
				ip_color := "00"
				if history.Contains(match[1]) {
					ip_color = "05"
				}
				proto_color := "08"
				if match[2] == "TCP" {
					proto_color = "02"
				} else if match[2] == "UDP" {
					proto_color = "06"
				}
				if ok {
					suffix = fmt.Sprintf("\00303%v\003", service)
				}
				msg = fmt.Sprintf("DROPPED \002\003%v%v\003\002 \00304=>\003 <blackbox>:\00304%v\003 \002\003%v%v\003\002 %v", ip_color, match[1], match[3], proto_color, match[2], suffix)
				if debug {
					fmt.Println(msg)
				} else {
					for _, channel := range config.Channels {
						go func() {
							var tmp bool
							c.Call("privmsg", &PrivMsg{channel, msg}, &tmp)
						}()
					}
				}
				now := time.Now()
				history.Push(&HistoryItem{match[1], &now})
			}
		}
	}()
	forever := make(chan bool)
	<-forever
}
