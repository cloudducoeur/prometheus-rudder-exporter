#!/bin/sh
systemctl daemon-reload
systemctl enable prometheus-rudder-exporter.service
