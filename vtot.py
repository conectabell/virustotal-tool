# -*- coding: utf-8 -*-
# Un script para suministrar archivos a virustotal
# Permite adjuntar un hash o archivo y devuelve el resultado
# Se necesita una API-KEY de Virustotal
# Creado por Charlie para conectabell.com
# -------------------------------------------------
import argparse
import postfile
import simplejson
import json
import urllib
import urllib2


descrip = str("Virustotal:\n "
"Utilidad para poder suministrar archivos a virustotal "
"a traves de la API. Tienes que definir tu clave de la "
"API, para ello registrate en VirusTotal.com"
)
APIKEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
current = ""


def comp(h):
    url = "https://www.virustotal.com/vtapi/v2/file/report"
    parameters = {"resource": h,
                  "apikey": APIKEY}
    data = urllib.urlencode(parameters)
    req = urllib2.Request(url, data)
    resp = urllib2.urlopen(req)
    jn = resp.read()
    return jn


def submit(f):
    host = "www.virustotal.com"
    selector = "https://www.virustotal.com/vtapi/v2/file/scan"
    fields = [("apikey", APIKEY)]
    file_to_send = open(f, "rb").read()
    files = [("file", f, file_to_send)]
    jsond = postfile.post_multipart(host, selector, fields, files)
    return jsond


parser = argparse.ArgumentParser(description=str(descrip))
parser.add_argument("-H", "--hash", help="Suministra un hash sha256")
parser.add_argument("-F", "--file", help="Suministra un archivo")
parser.add_argument("-c", "--calculate-hash",
help="Calcula el hash del archivo que le hemos suministrado")
parser.add_argument("-v", "--verbosity", help="activa la verbosidad",
                    action="store_true")
args = parser.parse_args()
#print args.echo

if args.file:
    d = submit(args.file)
    #d2 = comp(args.hash)
    dec = json.loads(d)
    hsh = str(dec["sha256"])
    print ">>> sha256sum: " + hsh
    while "total" not in dec:
        #print "entra en el bucle"
        d = comp(hsh)
        dec = json.loads(d)
    else:
        if str(dec["positives"]) == "0":
            print ">>> Archivo Limpio según Virustotal"
        else:
            print "TOTAL: " + str(dec["total"])
            print "POSITIVOS: " + str(dec["positives"])

if args.hash:
    d = comp(args.hash)
    if "total" in d:
        dec = json.loads(d)
        print "TOTAL: " + str(dec["total"])
        print "POSITIVOS: " + str(dec["positives"])
    else:
        print ">> Hash no encontrado"

if args.verbosity:
    print("Esta la Verbosidad y... la VERBOSIDAAAAD")

