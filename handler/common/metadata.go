package common

import (
	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/core/metadata/util"
)

const (
	vpsID      = "vpsid"
	logService = "logservice"
)

type Metadata struct {
	VpsID          int32
	LogServiceAddr string
}

func ParseMetadata(md mdata.Metadata) Metadata {
	m := Metadata{}
	m.VpsID = int32(mdutil.GetInt(md, vpsID))
	m.LogServiceAddr = mdutil.GetString(md, logService)
	return m
}
