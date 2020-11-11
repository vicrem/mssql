#!/bin/bash

/tmp/initialization.sh & \
exec gosu mssql /opt/mssql/bin/sqlservr
