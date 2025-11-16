package indexer

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/0gfoundation/0g-storage-client/common/util"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

var defaultIPLocationManager = IPLocationManager{}

type IPLocation struct {
	City     string `json:"city"`
	Region   string `json:"region"`
	Country  string `json:"country"`
	Location string `json:"loc"`
	Timezone string `json:"timezone"`
}

type IPLocationConfig struct {
	CacheFile          string
	CacheWriteInterval time.Duration
	AccessToken        string
}

// IPLocationManager manages IP locations.
type IPLocationManager struct {
	config IPLocationConfig
	items  sync.Map // ip -> *IPLocation
}

// InitDefaultIPLocationManager initializes the default `IPLocationManager`.
func InitDefaultIPLocationManager(config IPLocationConfig) {
	defaultIPLocationManager.config = config

	// try load from cached IP locations
	n, err := defaultIPLocationManager.read()
	if err != nil {
		logrus.WithError(err).Warn("Failed to read cached IP locations")
	} else {
		logrus.WithField("count", n).Info("Succeeded to read cached IP locations")
	}

	go util.Schedule(defaultIPLocationManager.write, config.CacheWriteInterval, "Failed to write IP locations once")
}

// All returns all cached IP locations.
func (manager *IPLocationManager) All() map[string]*IPLocation {
	all := make(map[string]*IPLocation)

	manager.items.Range(func(key, value any) bool {
		all[key.(string)] = value.(*IPLocation)
		return true
	})

	return all
}

func (manager *IPLocationManager) Get(ip string) (*IPLocation, bool) {
	val, ok := manager.items.Load(ip)
	if !ok {
		return nil, false
	}

	return val.(*IPLocation), true
}

// Query returns the cached IP location if any. Otherwise, retrieve from web API.
func (manager *IPLocationManager) Query(ip string) (*IPLocation, error) {
	if loc, ok := manager.items.Load(ip); ok {
		return loc.(*IPLocation), nil
	}

	var url string
	if len(manager.config.AccessToken) == 0 {
		url = fmt.Sprintf("http://ipinfo.io/%v/json", ip)
	} else {
		url = fmt.Sprintf("http://ipinfo.io/%v/json?token=%v", ip, manager.config.AccessToken)
	}

	resp, err := http.Get(url)
	if err != nil {
		return nil, errors.WithMessagef(err, "Failed to http GET from %v", url)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to read http response body")
	}

	var loc IPLocation
	if err = json.Unmarshal(body, &loc); err != nil {
		return nil, errors.WithMessage(err, "Failed to unmarshal Location data")
	}

	logger := logrus.WithFields(logrus.Fields{
		"ip":       ip,
		"timezone": loc.Timezone,
		"country":  loc.Country,
		"city":     loc.City,
		"loc":      loc.Location,
	})

	if len(loc.Timezone) > 0 && len(loc.Region) > 0 && len(loc.Country) > 0 && len(loc.City) > 0 && len(loc.Location) > 0 {
		manager.items.Store(ip, &loc)
		logger.Debug("New IP location detected")
	} else {
		logger.Warn("New IP location detected with partial fields")
	}

	return &loc, nil
}

// read reads IP locations from cache file.
func (manager *IPLocationManager) read() (int, error) {
	data, err := os.ReadFile(manager.config.CacheFile)
	if os.IsNotExist(err) {
		return 0, nil
	}

	if err != nil {
		return 0, errors.WithMessagef(err, "Failed to read file '%v'", manager.config.CacheFile)
	}

	var cached map[string]*IPLocation
	if err = json.Unmarshal(data, &cached); err != nil {
		return 0, errors.WithMessage(err, "Failed to unmarshal data")
	}

	for ip, loc := range cached {
		manager.items.Store(ip, loc)
	}

	return len(cached), nil
}

// write writes cached IP locations to file.
func (manager *IPLocationManager) write() error {
	all := manager.All()
	if len(all) == 0 {
		return nil
	}

	data, err := json.MarshalIndent(all, "", "    ")
	if err != nil {
		return errors.WithMessage(err, "Failed to marshal IP locations")
	}

	if err = os.WriteFile(manager.config.CacheFile, data, os.ModePerm); err != nil {
		return errors.WithMessage(err, "Failed to write IP locations to file")
	}

	logrus.WithField("count", len(all)).Info("Succeeded to write IP locations to file")

	return nil
}
