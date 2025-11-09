// Copyright 2017 Kumina, https://kumina.nl/
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"encoding/xml"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"

	goLibvirt "github.com/digitalocean/go-libvirt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/pvokhmyanin/libvirt_exporter/libvirt_schema"
	"gopkg.in/alecthomas/kingpin.v2"
)

// LibvirtExporter implements a Prometheus exporter for libvirt state.
type LibvirtExporter struct {
	uri                string
	exportNovaMetadata bool

	libvirtUpDesc            *prometheus.Desc
	libvirtDomainsNumberDesc *prometheus.Desc

	libvirtDomainStateCode         *prometheus.Desc
	libvirtDomainInfoMaxMemDesc    *prometheus.Desc
	libvirtDomainInfoMemoryDesc    *prometheus.Desc
	libvirtDomainInfoNrVirtCpuDesc *prometheus.Desc
	libvirtDomainInfoCpuTimeDesc   *prometheus.Desc

	libvirtDomainBlockRdBytesDesc         *prometheus.Desc
	libvirtDomainBlockRdReqDesc           *prometheus.Desc
	libvirtDomainBlockRdTotalTimesDesc    *prometheus.Desc
	libvirtDomainBlockWrBytesDesc         *prometheus.Desc
	libvirtDomainBlockWrReqDesc           *prometheus.Desc
	libvirtDomainBlockWrTotalTimesDesc    *prometheus.Desc
	libvirtDomainBlockFlushReqDesc        *prometheus.Desc
	libvirtDomainBlockFlushTotalTimesDesc *prometheus.Desc

	libvirtDomainInterfaceRxBytesDesc   *prometheus.Desc
	libvirtDomainInterfaceRxPacketsDesc *prometheus.Desc
	libvirtDomainInterfaceRxErrsDesc    *prometheus.Desc
	libvirtDomainInterfaceRxDropDesc    *prometheus.Desc
	libvirtDomainInterfaceTxBytesDesc   *prometheus.Desc
	libvirtDomainInterfaceTxPacketsDesc *prometheus.Desc
	libvirtDomainInterfaceTxErrsDesc    *prometheus.Desc
	libvirtDomainInterfaceTxDropDesc    *prometheus.Desc
}

// NewLibvirtExporter creates a new Prometheus exporter for libvirt.
func NewLibvirtExporter(uri string, exportNovaMetadata bool) (*LibvirtExporter, error) {
	var domainLabels []string
	if exportNovaMetadata {
		domainLabels = []string{"domain", "uuid", "name", "flavor", "project_name"}
	} else {
		domainLabels = []string{"domain", "uuid"}
	}
	return &LibvirtExporter{
		uri:                uri,
		exportNovaMetadata: exportNovaMetadata,
		libvirtUpDesc: prometheus.NewDesc(
			prometheus.BuildFQName("libvirt", "", "up"),
			"Whether scraping libvirt's metrics was successful.",
			nil,
			nil),
		libvirtDomainsNumberDesc: prometheus.NewDesc(
			prometheus.BuildFQName("libvirt", "", "domains_number"),
			"Number of domains.",
			nil,
			nil),
		libvirtDomainStateCode: prometheus.NewDesc(
			prometheus.BuildFQName("libvirt", "", "domain_state_code"),
			"State of the domain.",
			domainLabels,
			nil),
		libvirtDomainInfoMaxMemDesc: prometheus.NewDesc(
			prometheus.BuildFQName("libvirt", "domain_info", "maximum_memory_bytes"),
			"Maximum allowed memory of the domain, in bytes.",
			domainLabels,
			nil),
		libvirtDomainInfoMemoryDesc: prometheus.NewDesc(
			prometheus.BuildFQName("libvirt", "domain_info", "memory_usage_bytes"),
			"Memory usage of the domain, in bytes.",
			domainLabels,
			nil),
		libvirtDomainInfoNrVirtCpuDesc: prometheus.NewDesc(
			prometheus.BuildFQName("libvirt", "domain_info", "virtual_cpus"),
			"Number of virtual CPUs for the domain.",
			domainLabels,
			nil),
		libvirtDomainInfoCpuTimeDesc: prometheus.NewDesc(
			prometheus.BuildFQName("libvirt", "domain_info", "cpu_time_seconds_total"),
			"Amount of CPU time used by the domain, in seconds.",
			domainLabels,
			nil),
		libvirtDomainBlockRdBytesDesc: prometheus.NewDesc(
			prometheus.BuildFQName("libvirt", "domain_block_stats", "read_bytes_total"),
			"Number of bytes read from a block device, in bytes.",
			append(domainLabels, "source_file", "target_device"),
			nil),
		libvirtDomainBlockRdReqDesc: prometheus.NewDesc(
			prometheus.BuildFQName("libvirt", "domain_block_stats", "read_requests_total"),
			"Number of read requests from a block device.",
			append(domainLabels, "source_file", "target_device"),
			nil),
		libvirtDomainBlockRdTotalTimesDesc: prometheus.NewDesc(
			prometheus.BuildFQName("libvirt", "domain_block_stats", "read_seconds_total"),
			"Amount of time spent reading from a block device, in seconds.",
			append(domainLabels, "source_file", "target_device"),
			nil),
		libvirtDomainBlockWrBytesDesc: prometheus.NewDesc(
			prometheus.BuildFQName("libvirt", "domain_block_stats", "write_bytes_total"),
			"Number of bytes written from a block device, in bytes.",
			append(domainLabels, "source_file", "target_device"),
			nil),

		libvirtDomainBlockWrReqDesc: prometheus.NewDesc(
			prometheus.BuildFQName("libvirt", "domain_block_stats", "write_requests_total"),
			"Number of write requests from a block device.",
			append(domainLabels, "source_file", "target_device"),
			nil),
		libvirtDomainBlockWrTotalTimesDesc: prometheus.NewDesc(
			prometheus.BuildFQName("libvirt", "domain_block_stats", "write_seconds_total"),
			"Amount of time spent writing from a block device, in seconds.",
			append(domainLabels, "source_file", "target_device"),
			nil),
		libvirtDomainBlockFlushReqDesc: prometheus.NewDesc(
			prometheus.BuildFQName("libvirt", "domain_block_stats", "flush_requests_total"),
			"Number of flush requests from a block device.",
			append(domainLabels, "source_file", "target_device"),
			nil),
		libvirtDomainBlockFlushTotalTimesDesc: prometheus.NewDesc(
			prometheus.BuildFQName("libvirt", "domain_block_stats", "flush_seconds_total"),
			"Amount of time spent flushing of a block device, in seconds.",
			append(domainLabels, "source_file", "target_device"),
			nil),

		libvirtDomainInterfaceRxBytesDesc: prometheus.NewDesc(
			prometheus.BuildFQName("libvirt", "domain_interface_stats", "receive_bytes_total"),
			"Number of bytes received on a network interface, in bytes.",
			append(domainLabels, "source_bridge", "target_device"),
			nil),
		libvirtDomainInterfaceRxPacketsDesc: prometheus.NewDesc(
			prometheus.BuildFQName("libvirt", "domain_interface_stats", "receive_packets_total"),
			"Number of packets received on a network interface.",
			append(domainLabels, "source_bridge", "target_device"),
			nil),
		libvirtDomainInterfaceRxErrsDesc: prometheus.NewDesc(
			prometheus.BuildFQName("libvirt", "domain_interface_stats", "receive_errors_total"),
			"Number of packet receive errors on a network interface.",
			append(domainLabels, "source_bridge", "target_device"),
			nil),
		libvirtDomainInterfaceRxDropDesc: prometheus.NewDesc(
			prometheus.BuildFQName("libvirt", "domain_interface_stats", "receive_drops_total"),
			"Number of packet receive drops on a network interface.",
			append(domainLabels, "source_bridge", "target_device"),
			nil),
		libvirtDomainInterfaceTxBytesDesc: prometheus.NewDesc(
			prometheus.BuildFQName("libvirt", "domain_interface_stats", "transmit_bytes_total"),
			"Number of bytes transmitted on a network interface, in bytes.",
			append(domainLabels, "source_bridge", "target_device"),
			nil),
		libvirtDomainInterfaceTxPacketsDesc: prometheus.NewDesc(
			prometheus.BuildFQName("libvirt", "domain_interface_stats", "transmit_packets_total"),
			"Number of packets transmitted on a network interface.",
			append(domainLabels, "source_bridge", "target_device"),
			nil),
		libvirtDomainInterfaceTxErrsDesc: prometheus.NewDesc(
			prometheus.BuildFQName("libvirt", "domain_interface_stats", "transmit_errors_total"),
			"Number of packet transmit errors on a network interface.",
			append(domainLabels, "source_bridge", "target_device"),
			nil),
		libvirtDomainInterfaceTxDropDesc: prometheus.NewDesc(
			prometheus.BuildFQName("libvirt", "domain_interface_stats", "transmit_drops_total"),
			"Number of packet transmit drops on a network interface.",
			append(domainLabels, "source_bridge", "target_device"),
			nil),
	}, nil
}

func (e *LibvirtExporter) reportBlockStatsForDisk(ch chan<- prometheus.Metric, domainLabelValues []string, disk libvirt_schema.Disk, blockStats []goLibvirt.TypedParam) error {
	for _, blockStat := range blockStats {
		// Ullong and Llong are the only TypedParams we can encounter here, so this adhoc is sufficient
		getTypedParamValue := func(tpv goLibvirt.TypedParamValue) (float64, error) {
			if tpv.D == uint32(goLibvirt.TypedParamUllong) {
				v, ok := tpv.I.(uint64)
				if !ok {
					return 0, fmt.Errorf("type mismatch uint64: %#v", tpv.I)
				}

				return float64(v), nil
			}

			if tpv.D == uint32(goLibvirt.TypedParamLlong) {
				v, ok := tpv.I.(int64)
				if !ok {
					return 0, fmt.Errorf("type mismatch int64: %#v", tpv.I)
				}

				return float64(v), nil
			}

			return 0, fmt.Errorf("no suitable conversion for ParamType %d", tpv.D)
		}

		fieldValue, err := getTypedParamValue(blockStat.Value)
		if err != nil {
			return fmt.Errorf("field %q failed to convert: %w", blockStat.Field, err)
		}

		switch blockStat.Field {
		case "rd_bytes":
			ch <- prometheus.MustNewConstMetric(
				e.libvirtDomainBlockRdBytesDesc,
				prometheus.CounterValue,
				fieldValue,
				append(domainLabelValues, disk.Source.File, disk.Target.Device)...)

		case "rd_req":
			ch <- prometheus.MustNewConstMetric(
				e.libvirtDomainBlockRdReqDesc,
				prometheus.CounterValue,
				fieldValue,
				append(domainLabelValues, disk.Source.File, disk.Target.Device)...)

		case "rd_total_times":
			ch <- prometheus.MustNewConstMetric(
				e.libvirtDomainBlockRdTotalTimesDesc,
				prometheus.CounterValue,
				fieldValue/1e9,
				append(domainLabelValues, disk.Source.File, disk.Target.Device)...)

		case "wr_bytes":
			ch <- prometheus.MustNewConstMetric(
				e.libvirtDomainBlockWrBytesDesc,
				prometheus.CounterValue,
				fieldValue,
				append(domainLabelValues, disk.Source.File, disk.Target.Device)...)

		case "wr_req":
			ch <- prometheus.MustNewConstMetric(
				e.libvirtDomainBlockWrReqDesc,
				prometheus.CounterValue,
				fieldValue,
				append(domainLabelValues, disk.Source.File, disk.Target.Device)...)

		case "wr_total_times":
			ch <- prometheus.MustNewConstMetric(
				e.libvirtDomainBlockWrTotalTimesDesc,
				prometheus.CounterValue,
				fieldValue/1e9,
				append(domainLabelValues, disk.Source.File, disk.Target.Device)...)

		case "flush_operations":
			ch <- prometheus.MustNewConstMetric(
				e.libvirtDomainBlockFlushReqDesc,
				prometheus.CounterValue,
				fieldValue,
				append(domainLabelValues, disk.Source.File, disk.Target.Device)...)

		case "flush_total_times":

			ch <- prometheus.MustNewConstMetric(
				e.libvirtDomainBlockFlushTotalTimesDesc,
				prometheus.CounterValue,
				fieldValue/1e9,
				append(domainLabelValues, disk.Source.File, disk.Target.Device)...)

		}
	}

	return nil
}

// Describe returns metadata for all Prometheus metrics that may be exported.
func (e *LibvirtExporter) Describe(ch chan<- *prometheus.Desc) {
	ch <- e.libvirtUpDesc
	ch <- e.libvirtDomainsNumberDesc

	ch <- e.libvirtDomainStateCode
	ch <- e.libvirtDomainInfoMaxMemDesc
	ch <- e.libvirtDomainInfoMemoryDesc
	ch <- e.libvirtDomainInfoNrVirtCpuDesc
	ch <- e.libvirtDomainInfoCpuTimeDesc

	ch <- e.libvirtDomainBlockRdBytesDesc
	ch <- e.libvirtDomainBlockRdReqDesc
	ch <- e.libvirtDomainBlockRdTotalTimesDesc
	ch <- e.libvirtDomainBlockWrBytesDesc
	ch <- e.libvirtDomainBlockWrReqDesc
	ch <- e.libvirtDomainBlockWrTotalTimesDesc
	ch <- e.libvirtDomainBlockFlushReqDesc
	ch <- e.libvirtDomainBlockFlushTotalTimesDesc
}

// Collect scrapes Prometheus metrics from libvirt.
func (e *LibvirtExporter) Collect(ch chan<- prometheus.Metric) {
	err := e.CollectFromLibvirt(ch)
	if err == nil {
		ch <- prometheus.MustNewConstMetric(
			e.libvirtUpDesc,
			prometheus.GaugeValue,
			1.0)
	} else {
		log.Printf("Failed to scrape metrics: %s", err)
		ch <- prometheus.MustNewConstMetric(
			e.libvirtUpDesc,
			prometheus.GaugeValue,
			0.0)
	}
}

// CollectFromLibvirt obtains Prometheus metrics from all domains in a
// libvirt setup.
func (e *LibvirtExporter) CollectFromLibvirt(ch chan<- prometheus.Metric) error {
	uri, err := url.Parse(e.uri)
	if err != nil {
		return fmt.Errorf("parse URI %q: %w", e.uri, err)
	}

	conn, err := goLibvirt.ConnectToURI(uri)
	if err != nil {
		return fmt.Errorf("connect to libvirt: %w", err)
	}
	defer conn.ConnectClose()

	domainIds, _, err := conn.ConnectListAllDomains(1, goLibvirt.ConnectListDomainsActive|goLibvirt.ConnectListDomainsInactive)
	if err != nil {
		return fmt.Errorf("list all domains: %w", err)
	}
	// number of domains
	ch <- prometheus.MustNewConstMetric(
		e.libvirtDomainsNumberDesc,
		prometheus.GaugeValue,
		float64(len(domainIds)))

	for _, id := range domainIds {
		domain, err := conn.DomainLookupByUUID(id.UUID)
		if err == nil {
			err = e.CollectDomain(ch, conn, domain)
			if err != nil {
				return fmt.Errorf("collect stats for domain %q: %w", domain.Name, err)
			}
		}
	}

	return nil
}

// CollectDomain extracts Prometheus metrics from a libvirt domain.
func (e *LibvirtExporter) CollectDomain(ch chan<- prometheus.Metric, conn *goLibvirt.Libvirt, domain goLibvirt.Domain) error {
	// Decode XML description of domain to get block device names, etc.
	xmlDesc, err := conn.DomainGetXMLDesc(domain, 0)
	if err != nil {
		return fmt.Errorf("get domain xml config: %w", err)
	}
	var desc libvirt_schema.Domain
	err = xml.Unmarshal([]byte(xmlDesc), &desc)
	if err != nil {
		return fmt.Errorf("unmarshall domain config %w", err)
	}

	domainUUID := desc.UUID
	domainName := domain.Name
	// Extract domain label valuies
	var domainLabelValues []string
	if e.exportNovaMetadata {
		var (
			novaName        = desc.Metadata.NovaInstance.Name
			novaFlavor      = desc.Metadata.NovaInstance.Flavor.Name
			novaProjectName = desc.Metadata.NovaInstance.Owner.ProjectName
		)
		domainLabelValues = []string{domainName, domainUUID, novaName, novaFlavor, novaProjectName}
	} else {
		domainLabelValues = []string{domainName, domainUUID}
	}

	// Report domain info.

	infoState, infoMaxMem, infoMemory, infoNrVirtCpu, infoCpuTime, err := conn.DomainGetInfo(domain)
	if err != nil {
		return fmt.Errorf("domain get info: %w", err)
	}
	ch <- prometheus.MustNewConstMetric(
		e.libvirtDomainStateCode,
		prometheus.GaugeValue,
		float64(infoState),
		domainLabelValues...)

	ch <- prometheus.MustNewConstMetric(
		e.libvirtDomainInfoMaxMemDesc,
		prometheus.GaugeValue,
		float64(infoMaxMem)*1024,
		domainLabelValues...)
	ch <- prometheus.MustNewConstMetric(
		e.libvirtDomainInfoMemoryDesc,
		prometheus.GaugeValue,
		float64(infoMemory)*1024,
		domainLabelValues...)
	ch <- prometheus.MustNewConstMetric(
		e.libvirtDomainInfoNrVirtCpuDesc,
		prometheus.GaugeValue,
		float64(infoNrVirtCpu),
		domainLabelValues...)
	ch <- prometheus.MustNewConstMetric(
		e.libvirtDomainInfoCpuTimeDesc,
		prometheus.CounterValue,
		float64(infoCpuTime)/1e9,
		domainLabelValues...)

	// Block and Net stats can only be obtained for a running domain, end here for inactive domains
	state, _, err := conn.DomainGetState(domain, 0)
	if goLibvirt.DomainState(state) != goLibvirt.DomainRunning && goLibvirt.DomainState(state) != goLibvirt.DomainPaused {
		return nil
	}

	// Report block device statistics.
	for _, disk := range desc.Devices.Disks {
		if disk.Device == "cdrom" || disk.Device == "fd" {
			continue
		}

		_, nParams, err := conn.DomainBlockStatsFlags(domain, disk.Target.Device, 0, 0)
		if err != nil {
			return fmt.Errorf("get nparam count for block stats %q for disk %q : %w", domain.Name, disk.Target.Device, err)
		}

		blockStats, _, err := conn.DomainBlockStatsFlags(domain, disk.Target.Device, nParams, 0)
		if err != nil {
			return fmt.Errorf("collect block stats %q for disk %q : %w", domain.Name, disk.Target.Device, err)
		}

		if err := e.reportBlockStatsForDisk(ch, domainLabelValues, disk, blockStats); err != nil {
			return fmt.Errorf("report block stats %q for disk %q : %w", domain.Name, disk.Target.Device, err)
		}

	}

	// Report network interface statistics.
	for _, iface := range desc.Devices.Interfaces {
		if iface.Target.Device == "" {
			continue
		}
		rRxBytes, rRxPackets, rRxErrs, rRxDrop, rTxBytes, rTxPackets, rTxErrs, rTxDrop, err := conn.DomainInterfaceStats(domain, iface.Target.Device)
		if err != nil {
			return fmt.Errorf("collect network stats %q for interface %q : %w", domain.Name, iface.Target.Device, err)
		}

		ch <- prometheus.MustNewConstMetric(
			e.libvirtDomainInterfaceRxBytesDesc,
			prometheus.CounterValue,
			float64(rRxBytes),
			append(domainLabelValues, iface.Source.Bridge, iface.Target.Device)...)
		ch <- prometheus.MustNewConstMetric(
			e.libvirtDomainInterfaceRxPacketsDesc,
			prometheus.CounterValue,
			float64(rRxPackets),
			append(domainLabelValues, iface.Source.Bridge, iface.Target.Device)...)
		ch <- prometheus.MustNewConstMetric(
			e.libvirtDomainInterfaceRxErrsDesc,
			prometheus.CounterValue,
			float64(rRxErrs),
			append(domainLabelValues, iface.Source.Bridge, iface.Target.Device)...)
		ch <- prometheus.MustNewConstMetric(
			e.libvirtDomainInterfaceRxDropDesc,
			prometheus.CounterValue,
			float64(rRxDrop),
			append(domainLabelValues, iface.Source.Bridge, iface.Target.Device)...)
		ch <- prometheus.MustNewConstMetric(
			e.libvirtDomainInterfaceTxBytesDesc,
			prometheus.CounterValue,
			float64(rTxBytes),
			append(domainLabelValues, iface.Source.Bridge, iface.Target.Device)...)
		ch <- prometheus.MustNewConstMetric(
			e.libvirtDomainInterfaceTxPacketsDesc,
			prometheus.CounterValue,
			float64(rTxPackets),
			append(domainLabelValues, iface.Source.Bridge, iface.Target.Device)...)
		ch <- prometheus.MustNewConstMetric(
			e.libvirtDomainInterfaceTxErrsDesc,
			prometheus.CounterValue,
			float64(rTxErrs),
			append(domainLabelValues, iface.Source.Bridge, iface.Target.Device)...)
		ch <- prometheus.MustNewConstMetric(
			e.libvirtDomainInterfaceTxDropDesc,
			prometheus.CounterValue,
			float64(rTxDrop),
			append(domainLabelValues, iface.Source.Bridge, iface.Target.Device)...)
	}

	return nil
}

func main() {
	var (
		app                       = kingpin.New("libvirt_exporter", "Prometheus metrics exporter for libvirt")
		listenAddress             = app.Flag("web.listen-address", "Address to listen on for web interface and telemetry.").Default(":9177").String()
		metricsPath               = app.Flag("web.telemetry-path", "Path under which to expose metrics.").Default("/metrics").String()
		libvirtURI                = app.Flag("libvirt.uri", "Libvirt URI from which to extract metrics.").Default("qemu:///system").String()
		libvirtExportNovaMetadata = app.Flag("libvirt.export-nova-metadata", "Export OpenStack Nova specific labels from libvirt domain xml").Default("false").Bool()
	)
	kingpin.MustParse(app.Parse(os.Args[1:]))

	exporter, err := NewLibvirtExporter(*libvirtURI, *libvirtExportNovaMetadata)
	if err != nil {
		panic(err)
	}
	prometheus.MustRegister(exporter)

	http.Handle(*metricsPath, promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`
			<html>
			<head><title>Libvirt Exporter</title></head>
			<body>
			<h1>Libvirt Exporter</h1>
			<p><a href='` + *metricsPath + `'>Metrics</a></p>
			</body>
			</html>`))
	})
	log.Fatal(http.ListenAndServe(*listenAddress, nil))
}
