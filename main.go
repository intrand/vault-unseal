// Copyright (c) Liam Stanley <me@liamstanley.io>. All rights reserved. Use
// of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/apex/log"
	"github.com/apex/log/handlers/json"
	"github.com/apex/log/handlers/logfmt"
	"github.com/apex/log/handlers/text"
	vapi "github.com/hashicorp/vault/api"
	flags "github.com/jessevdk/go-flags"
	_ "github.com/joho/godotenv/autoload"
	"github.com/phayes/permbits"
	yaml "gopkg.in/yaml.v2"
)

var (
	version = ""
	commit  = ""
	date    = ""
	builtBy = ""
)

// Config is a combo of the flags passed to the cli and the configuration file (if used).
type Config struct {
	Version    bool   `short:"v" long:"version" description:"display the version of vault-unseal and exit"`
	Debug      bool   `short:"d" long:"debug" description:"enable debugging (extra logging)"`
	ConfigPath string `env:"config_path" short:"c" long:"config" description:"path to configuration file" value-name:"PATH"`

	Log struct {
		Path   string `env:"log_path" long:"path" description:"path to log output to" value-name:"PATH"`
		Quiet  bool   `env:"log_quiet" long:"quiet" description:"disable logging to stdout (also: see levels)"`
		Level  string `env:"log_level" long:"level" default:"info" choice:"debug" choice:"info" choice:"warn" choice:"error" choice:"fatal"  description:"logging level"`
		JSON   bool   `env:"log_json" long:"json" description:"output logs in JSON format"`
		Pretty bool   `env:"log_pretty" long:"pretty" description:"output logs in a pretty colored format (cannot be easily parsed)"`
	} `group:"Logging Options" namespace:"log"`

	CheckInterval    time.Duration `env:"check_interval" long:"check-interval" description:"frequency of sealed checks against nodes" yaml:"check_interval"`
	MaxCheckInterval time.Duration `env:"max_check_interval" long:"max-check-interval" description:"max time that vault-unseal will wait for an unseal check/attempt" yaml:"max_check_interval"`

	AllowSingleNode bool     `env:"allow_single_node" long:"allow-single-node" description:"allow vault-unseal to run on a single node" yaml:"allow_single_node" hidden:"true"`
	Nodes           []string `env:"nodes" long:"nodes" env-delim:"," description:"nodes to connect/provide tokens to (can be provided multiple times & uses comma-separated string for environment variable)" yaml:"vault_nodes"`
	CaPath          string   `env:"tls_ca_path" long:"tls-ca-path" description:"path to certificate authority public tls certificate file" yaml:"tls_ca_path"`
	TLSSkipVerify   bool     `env:"tls_skip_verify" long:"tls-skip-verify" description:"disables tls certificate validation: DO NOT DO THIS" yaml:"tls_skip_verify"`
	Tokens          []string `env:"tokens" long:"tokens" env-delim:"," description:"tokens to provide to nodes (can be provided multiple times & uses comma-separated string for environment variable)" yaml:"unseal_tokens"`

	lastModifiedCheck time.Time
}

var (
	conf = &Config{
		CheckInterval: 30 * time.Second,
	}

	logger log.Interface
)

func newVault(addr string) (vault *vapi.Client) {
	var err error

	vconfig := vapi.DefaultConfig()
	vconfig.Address = addr
	vconfig.MaxRetries = 0
	vconfig.Timeout = 15 * time.Second

	hashiTlsConf := vapi.TLSConfig{
		Insecure: conf.TLSSkipVerify,
		CAPath:   conf.CaPath,
	}

	if err = vconfig.ConfigureTLS(&hashiTlsConf); err != nil {
		logger.WithError(err).Fatal("error initializing tls config")
	}

	if vault, err = vapi.NewClient(vconfig); err != nil {
		logger.Fatalf("error creating vault client: %v", err)
	}

	return vault
}

func main() {
	var err error
	if _, err = flags.Parse(conf); err != nil {
		if FlagErr, ok := err.(*flags.Error); ok && FlagErr.Type == flags.ErrHelp {
			os.Exit(0)
		}
		os.Exit(1)
	}

	if conf.Version {
		fmt.Printf("vault-unseal version: %s [%s] (%s, %s), compiled %s by %s\n", version, commit, runtime.GOOS, runtime.GOARCH, date, builtBy)
		os.Exit(0)
	}

	// Initialize logging.
	initLogger := &log.Logger{}
	if conf.Debug {
		initLogger.Level = log.DebugLevel
	} else {
		initLogger.Level = log.MustParseLevel(conf.Log.Level)
	}

	logWriters := []io.Writer{}

	if conf.Log.Path != "" {
		logFileWriter, err := os.OpenFile(conf.Log.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o666)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error opening log file %q: %v", conf.Log.Path, err)
			os.Exit(1)
		}
		defer logFileWriter.Close()

		logWriters = append(logWriters, logFileWriter)
	}

	if !conf.Log.Quiet {
		logWriters = append(logWriters, os.Stdout)
	} else {
		logWriters = append(logWriters, io.Discard)
	}

	if conf.Log.JSON {
		initLogger.Handler = json.New(io.MultiWriter(logWriters...))
	} else if conf.Log.Pretty {
		initLogger.Handler = text.New(io.MultiWriter(logWriters...))
	} else {
		initLogger.Handler = logfmt.New(io.MultiWriter(logWriters...))
	}

	logger = initLogger.WithFields(log.Fields{
		"version": version,
	})

	if err := readConfig(conf.ConfigPath); err != nil {
		logger.WithError(err).Fatal("error reading config")
	}

	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())

	for _, addr := range conf.Nodes {
		logger.WithField("addr", addr).Info("invoking worker")
		wg.Add(1)
		go worker(ctx, &wg, addr)
	}

	if conf.ConfigPath != "" {
		go func() {
			for {
				time.Sleep(15 * time.Second)

				if err := readConfig(conf.ConfigPath); err != nil {
					logger.WithError(err).Fatal("error reading config")
				}
			}
		}()
	}

	go func() {
		catch()
		cancel()
	}()

	wg.Wait()
}

func readConfig(path string) error {
	var err error
	var fi os.FileInfo

	if path != "" {
		fi, err = os.Stat(path)
		if err != nil {
			return err
		}

		if perms := permbits.FileMode(fi.Mode()); perms != 0o600 &&
			perms != 0o640 &&
			perms != 0o660 &&
			perms != 0o400 &&
			perms != 0o440 &&
			perms != 0o460 {
			return fmt.Errorf("permissions of %q are insecure: %s, please use 0660 or less", path, perms)
		}

		// Check to see if it's updated.
		if fi.ModTime() == conf.lastModifiedCheck {
			return nil
		}

		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		if err := yaml.Unmarshal(b, conf); err != nil {
			return err
		}
	}

	if conf.CheckInterval < 5*time.Second {
		conf.CheckInterval = 5 * time.Second
	}
	if conf.MaxCheckInterval < conf.CheckInterval {
		// Default to 2x.
		conf.MaxCheckInterval = conf.CheckInterval * time.Duration(2)
	}

	if len(conf.Nodes) < 3 {
		if !conf.AllowSingleNode {
			return errors.New("not enough nodes in node list (must have at least 3!)")
		}

		logger.Warn("running with less than 3 nodes. this is not recommended")
	}

	if len(conf.Tokens) < 1 {
		return errors.New("no tokens found in config")
	}

	if len(conf.Tokens) >= 3 {
		logger.Warnf("found %d tokens in the config, make sure this is not a security risk", len(conf.Tokens))
	}

	if path != "" {
		logger.WithField("path", path).Info("updated config")
		conf.lastModifiedCheck = fi.ModTime()
	}

	return nil
}

func catch() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	<-signals
	logger.Info("invoked termination, cleaning up")
}
