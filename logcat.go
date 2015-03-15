package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/ActiveState/tail"
	"github.com/cenkalti/rpc2"
	"io/ioutil"
	"net"
	"os"
	"regexp"
)

type PrivMsg struct {
	Target, Text string
}

func init() {
	var err error
	config, err = NewConfig("./logcat.json")
	if err != nil {
		panic(err)
	}
}

type Config struct {
	Channels []string `json:"channels"`
	Logfile  string   `json:"logfile"`
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
		go c.Run()

		c.Call("register", struct{}{}, &reply)

		for _, channel := range config.Channels {
			c.Call("join", channel, &reply)
		}
	}

	go func() {
		iptables := regexp.MustCompile("badguy dropped: .*SRC=([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}) .* DPT=([0-9]{1,5})")
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
				msg := fmt.Sprintf("DROPPED %v => <blackbox>:%v", match[1], match[2])
				if debug {
					fmt.Println(msg)
				} else {
					for _, channel := range config.Channels {
						go c.Call("privmsg", &PrivMsg{channel, msg}, &reply)
					}
				}
			}
		}
	}()
	forever := make(chan bool)
	<-forever
}
