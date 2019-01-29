## zeeky

Detect cobalt strike activity.

## Installation

- Install bro 2.6 (we built from source)
- Install kafka, af_packet plugins for bro
- Install telegraf (or download binary of telegraf)
- Install InfluxDB or use one of existing InfluxDB instances
- Have python3 and venv. Create a separate virtual environment (e.g. /srv/cobalt-activity). Activate the virtual environment and install influxdb, numpy, scipy, kafka, python-snappy using pip

## Configuration

### bro
- copy 2 custom scripts (bro.bro, packet_bin.bro) into share/bro/site
- copy modified local.bro script into the same place
- edit node.cfg as appropriate (set interface, configure CPUs), see sample config on git
- deploy and run bro (using broctl, deploy)
### InfluxDB and telegraf
- run InfluxDB (no changes there)
- copy telegraf.config from git. Modify InfluxDB address in the config (line ~93). Check in telegraf.config (around line 4070) under [[inputs.logparser]] the path for "files" to match the location of bro logs.
- run telegraf with this config.
- check that data starts to come into InfluxDB. Run influx client. Check the database telegraf appeared. "use telegraf". Check values start to come in: "select count(*) from packet_int where time > now() - 5m". If values don't come in check again the path in telegraf.config, check that there is a packet_bin.log in the bro log directory.
### python
- copy beacons.py and beacons_run.sh from git. Make them executable (chmod a+x beacons*.*)
- modify InfluxDB connection settings in beacons.py (line 17) (currently assumed to be run on the localhost)
- modify path of the python virtual env in the beacons_run.sh (/srv/cobalt-activity currently assumed)
- adjust kafka broker addresses in bro.bro (line 5), beacons.py (line 15)
- run beacons_run.sh until finished to check that there are no errors (this sends "starting beacons.py" msg to kafka/cobalt-activity, if you don't receive it kafka broker address might need a fix). You can comment out "kafka_msg({ 'msg': 'Started beacons.py'})" if you don't need it.
- install beacons_run.sh to run in crontab e.g. (adjust path of the script):
*/3 * * * * /srv/cobalt-activity/scripts/beacons_run.sh
- check that all types of events start to come to kafka topic cobalt-activity (they will come only after there are some events to report).
