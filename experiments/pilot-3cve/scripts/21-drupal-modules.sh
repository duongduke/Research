#!/usr/bin/env bash
# Ca B — Drupal module configuration states (CVE-2019-6340 preconditions).
# Builds and records the three planned states:
#   (i)  REST core enabled            (canonical: optional rest.resource.entity.node,
#                                      hal_json + basic_auth — Drupal core's own config)
#   (ii) REST disabled + JSON:API on  (JSON:API is NOT core in Drupal 8.6; the
#                                      contributed drupal/jsonapi 8.x-1.24 is used)
#   (iii) both disabled
# Also creates one article node so the endpoints are observable.
#
# GROUND TRUTH ONLY (drush). HTTP probes are deployment smoke checks only.
set -euo pipefail
C_NAME="$1"    # pilot-drupal-vuln | pilot-drupal-fixed
PORT="$2"      # 8083 | 8084
LAB="$HOME/pilot-lab"
DR() { docker exec -w /var/www/html "$C_NAME" drush "$@"; }
enabled_mods() { DR pm:list --type=module --status=enabled --field=name --format=list 2>/dev/null | grep -E '^(rest|jsonapi|serialization|hal|basic_auth)$' | paste -sd, - || true; }

# --- ensure the contributed JSON:API module is present -----------------------
if ! docker exec "$C_NAME" test -d /var/www/html/modules/jsonapi; then
  mkdir -p /tmp/pilot-jx && tar xzf "$LAB/releases/jsonapi-8.x-1.24.tar.gz" -C /tmp/pilot-jx
  docker cp /tmp/pilot-jx/jsonapi "$C_NAME":/var/www/html/modules/jsonapi
fi

echo "===== $C_NAME (:$PORT) ====="
echo "-- create one article node (idempotent) --"
DR php:eval '
if (!\Drupal::entityQuery("node")->condition("title","Pilot article")->execute()) {
  $n = \Drupal\node\Entity\Node::create([
    "type"=>"article","title"=>"Pilot article",
    "body"=>["value"=>"<p>pilot node</p>","format"=>"basic_html"],"status"=>1]);
  $n->save(); echo "created nid=".$n->id().PHP_EOL;
} else { echo "node exists".PHP_EOL; }' 2>&1 | tail -1

rest_on() { # enable REST modules + core optional entity.node resource
  DR pm:enable rest serialization hal basic_auth -y >/dev/null 2>&1
  DR pm:uninstall jsonapi -y >/dev/null 2>&1 || true
  DR php:eval '
    $c=\Drupal::configFactory()->getEditable("rest.resource.entity.node");
    $c->setData(["langcode"=>"en","status"=>true,
      "dependencies"=>["module"=>["basic_auth","hal","node"]],
      "id"=>"entity.node","plugin_id"=>"entity:node","granularity"=>"resource",
      "configuration"=>["methods"=>["GET","POST","PATCH","DELETE"],
                        "formats"=>["hal_json"],"authentication"=>["basic_auth"]]])->save();
    echo "rest.resource.entity.node configured".PHP_EOL;' 2>&1 | tail -1
}
rest_off() { DR pm:uninstall rest -y >/dev/null 2>&1 || true; }
jsonapi_on() { DR pm:enable jsonapi serialization -y >/dev/null 2>&1; }
jsonapi_off() { DR pm:uninstall jsonapi -y >/dev/null 2>&1 || true; }

state_report() { # $1=label
  echo "-- $1 --"
  echo "   enabled: $(enabled_mods)"
  echo "   REST    /node/1?_format=hal_json -> $(curl -s -o /tmp/dn -w '%{http_code}' -u admin:${WP_ADMIN_PASSWORD:-changeme} -H 'Accept: application/hal+json' "http://127.0.0.1:$PORT/node/1?_format=hal_json")"
  echo "   JSONAPI /jsonapi/node/article    -> $(curl -s -o /tmp/dj -w '%{http_code}' -H 'Accept: application/vnd.api+json' "http://127.0.0.1:$PORT/jsonapi/node/article")"
}

echo "== state (i): REST on, JSON:API off =="
jsonapi_off; rest_on; state_report "state (i)"

echo "== state (ii): REST off, JSON:API on =="
rest_off; jsonapi_on; state_report "state (ii)"

echo "== state (iii): both off =="
rest_off; jsonapi_off; state_report "state (iii)"

echo "== restore state (i): REST on, JSON:API off (final) =="
jsonapi_off; rest_on; state_report "state (i, final)"
