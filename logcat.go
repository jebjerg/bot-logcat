package main

import (
	cfg "github.com/jebjerg/go-bot/bot/config"

	"bufio"
	"flag"
	"fmt"
	"github.com/ActiveState/tail"
	"github.com/cenkalti/rpc2"
	"github.com/jebjerg/fixedhistory"
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
	num int
	v   string
	t   *time.Time
}

type logcat_conf struct {
	Channels []string `json:"channels"`
	BotHost  string   `json:"bot_host"`
	Logfile  string   `json:"logfile"`
	Services string   `json:"services"`
	MaxItems int      `json:"max_items"`
	Interval int      `json:"cleanup_interval"`
}

var history *fixedhistory.FixedArray
var services map[string]string
var config *logcat_conf
var debug bool

func init() {
	config = &logcat_conf{}
	err := cfg.NewConfig(config, "logcat.json")
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

	f, err := os.Open(config.Services)
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

func main() {
	flag.BoolVar(&debug, "debug", false, "debug mode")
	flag.Parse()

	var c *rpc2.Client

	if debug == false {
		conn, err := net.Dial("tcp", config.BotHost)
		if err != nil {
			fmt.Println("connect error:", err)
			os.Exit(1)
		}
		c = rpc2.NewClient(conn)
		go func() {
			for {
				c.Run()
			}
		}()

		c.Call("register", struct{}{}, nil)

		for _, channel := range config.Channels {
			c.Call("join", channel, nil)
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
				if item := history.Get(match[1]); item != nil {
					item := item.(*HistoryItem)
					if item.num <= 1 {
						ip_color = "00"
					} else if item.num <= 10 {
						ip_color = "03"
					} else if item.num <= 50 {
						ip_color = "02"
					} else if item.num <= 100 {
						ip_color = "08"
					} else if item.num > 100 {
						ip_color = "04"
					}
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
				if history.Contains(match[1]) {
					item := history.Get(match[1])
					if item != nil {
						item := item.(*HistoryItem)
						item.num += 1
						now := time.Now()
						item.t = &now
						history.Push(item)
					}
				} else {
					now := time.Now()
					history.Push(&HistoryItem{num: 1, v: match[1], t: &now})
				}
			}
		}
	}()
	forever := make(chan bool)
	<-forever
}
