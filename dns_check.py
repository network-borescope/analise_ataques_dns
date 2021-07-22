from sys import argv, exit
import datetime
from ip_to_nome_lat_lon import site_from_ip

VERSION = "v1"

arguments = argv[1:]

if len(arguments) == 1:
    filename = arguments[0]
else:
    exit(1)
    
def hour_to_timedelta(d_hora):
    hour, min, sec = d_hora.split(":")
    
    return datetime.timedelta(hours=int(hour), minutes=int(min), seconds=float(sec))

def dns_req_eof(last_timedelta, current_timedelta, delta_seconds=30):
    delta = datetime.timedelta(seconds=delta_seconds)
    
    if current_timedelta <= last_timedelta - delta: return False
    
    return True

def get_query(items):
    n = len(items)
    i = 7 # indice inicial
    
    query_type = None
    query = None
    while i < n:
        if len(items[i]) > 0 and items[i][-1] == "?": # query type
            query_type = items[i]

            i += 1
            if not i < n: return None

            if len(items[i]) > 0 and items[i][-1] == ".": # query termina com "."
                query = items[i][:-1] # remove o ponto

                return query
            
            return None
        
        i += 1
    
    return None

open_dns = {}
with open("open_dns_list.txt", "r") as f:
    for line in f:
        line = line.strip()

        items = line.split("|")
        name = items[0]

        for ip in items[1:]:
            open_dns[ip] = name

dns_match_total = {} # { f"{data[D_SIP]} {data[D_SPORT]} {data[D_DIP]} {query_id} {query}": [dns_req, dns_resp, req_time] }

# {
# ip: {
#   "req_count": 0, 
#   "req_sem_resp_count:": 0,
#   "req_eof_count": 0,
#   "pairs_count": 0,
#   "data[D_SIP]} {data[D_SPORT]} {data[D_DIP]} {query_id} {query}": [dns_req, dns_resp, req_time]
#   }
# }
dns_match_ip = {}

REQUEST = 0
RESPONSE = 1
REQUEST_TIME = 2

dns_count = [0, 0, 0, 0, 0, 0, 0]
TOTAL_REQ = 0
TOTAL_PAIRS = 1
WITHOUT_PAIR = 2
REQ_EOF = 3
TOTAL_RESP = 4
REPEATED_REQ = 5
CONV_ENTRE_SERVIDORES = 6

know_ips = {}

fin = open(filename, "r")

filename = filename.split(".")[0]

f_resp = open(f"{VERSION}_{filename}_resp_sem_req.txt", "w")

data = []
# data positions
D_DATA = 0
D_HORA = 1
D_TTL = 2
D_PROTO = 3
D_IP_ID = 4
D_SIP= 5
D_SPORT = 6
D_DIP= 7
D_IDC = 8
D_QUERY = 9
D_HOST = 10
D_US_AG = 11
D_DIST = 12
D_IDD = 13


count = 0

for line in fin:
    count+=1
    if count % 1000000 == 0: print(count)

    ident = 0
    altura = 0
    if len(line) == 0: continue

    # verifica se eh a linha de header
    while line[0] == ' ' or line[0] == '\t':
        if line[0] == '\t': ident += 8
        else: ident+=1
        line =line[1:]

    altura = ident/4
    #print (altura)

    if altura == 0:
        # reinicia as variaveis de memoria
        key = ""
        data = []

        # inicia o processamento do novo hash
        clean_line = line.strip()
        items = clean_line.split(" ")

        if len(items) < 6: continue
        if items[2] != "IP": continue

        n = len(items)

        # [data, hora, val_ttl, val_proto, val_ip_id ]
        val_proto = items[15][1:-2]
        data = [ items[0], items[1], items[6].strip(","), val_proto, items[8].strip(","), "0", "0", "0", "0", "0", "0", "0", "0", "0" ]
        #print("Data> ", data)
        if data[D_TTL] == "oui":
             data = []
             continue

        dist = int(data[D_TTL])
        if dist < 64: dist = 64 - dist
        elif dist < 128: dist = 128 - dist
        else: dist = 255 - dist
        data[D_DIST] = str(dist)

    # linha do corpo
    elif altura == 1:

        items = line.strip().split(" ")
        if len(items) == 0 or len(items[0]) == 0: continue

        # testa para ver se eh o sub-header
        if altura == 1 and len(items) > 6:
            c = items[0][0]
            if c >= '0' and c <= '9':
                ip_src_a = items[0].split(".")

                ip_src = ip_src_a[0] + "." + ip_src_a[1] + "." + ip_src_a[2] + "." + ip_src_a[3]
                data[D_SIP] = ip_src
                ip_len = len(ip_src_a)
                if ip_len < 5: continue
                data[D_SPORT] = ip_src_a[4]


                ip_dst_a = items[2].split(".")
                ip_len = len(ip_dst_a)

                # remove o ":" do final dos campos do ip_dst
                ip_dst_a[ip_len-1] = ip_dst_a[ip_len-1] [:-1]

                # reconstitui o ip
                ip_dst = ip_dst_a[0] + "." + ip_dst_a[1] + "." + ip_dst_a[2] + "." + ip_dst_a[3]
                data[D_DIP] = ip_dst

                if ip_len == 4:
                    port_dst = "0"
                else:
                    port_dst = ip_dst_a[4]

                    # concentra portas sem interesse na porta "0"
                    proto_port = data[D_PROTO] + ":" + port_dst

                
                if (data[D_PROTO] + ":" + data[D_SPORT] + ":" + port_dst) == "17:53:53": # conversa entre servidores DNS
                    dns_count[CONV_ENTRE_SERVIDORES] += 1

                elif proto_port == "17:53": # se for dns request
                    if len(items) < 10:# or (items[7] != 'A?' and items[8] != 'A?'):
                        continue

                    if items[6][0] >= '0' and items[6][0] <= '9':
                        query_id = items[6].replace("+", "")
                        query_id = query_id.replace("%", "")

                        query = get_query(items)
                        if query is None: continue

                        dns_count[TOTAL_REQ] += 1
                        
                        key = f"{data[D_SIP]} {data[D_SPORT]} {data[D_DIP]} {query_id} {query}"

                        if key not in dns_match_total:
                            dns_match_total[key] = [f"{data[D_HORA]} {line.strip()}", None, None]
                            
                            dns_match_total[key][REQUEST_TIME] = hour_to_timedelta(data[D_HORA])
                                                    
                        # query repetida
                        else:
                            dns_count[REPEATED_REQ] += 1
                        
                        #key_interna = data[D_SIP]
                        result = site_from_ip(data[D_SIP])
                        if result[6] == "1": key_interna = data[D_SIP]#key_interna = f"{ip_src_a[0]}.{ip_src_a[1]}.0.0/16"
                        else: key_interna = result[0]

                        if key_interna not in dns_match_ip:
                            dns_match_ip[key_interna] = {}

                            dns_match_ip[key_interna][key] = [1, None, hour_to_timedelta(data[D_HORA])]

                            dns_match_ip[key_interna]["req_count"] = 1
                            dns_match_ip[key_interna]["req_sem_resp_count"] = 0
                            dns_match_ip[key_interna]["req_eof_count"] = 0
                            dns_match_ip[key_interna]["pairs_count"] = 0
                        
                        elif key not in dns_match_ip[key_interna]:
                            dns_match_ip[key_interna][key] = [1, None, hour_to_timedelta(data[D_HORA])]
                            dns_match_ip[key_interna]["req_count"] += 1

                elif (data[D_PROTO] + ":" + data[D_SPORT]) == "17:53": # dns response
                    

                    if items[6][0] >= '0' and items[6][0] <= '9':
                        query_id = items[6].replace("*", "")
                        query_id = query_id.replace("-", "")
                        query_id = query_id.replace("|", "")
                        query_id = query_id.replace("$", "")

                        query = get_query(items)
                        if query is None: continue
                        
                        key = f"{data[D_DIP]} {port_dst} {data[D_SIP]} {query_id} {query}"

                        dns_count[TOTAL_RESP] += 1

                        if key in dns_match_total:
                            if dns_match_total[key][RESPONSE] is None:
                                dns_match_total[key][RESPONSE] = f"{data[D_HORA]} {line.strip()}"
                                
                                dns_count[TOTAL_PAIRS] += 1
                        else:
                            print(f"{data[D_HORA]} {line.strip()}", file=f_resp)
                        
                        #key_interna = data[D_DIP]
                        result = site_from_ip(data[D_DIP])
                        if result[6] == "1": key_interna = data[D_DIP]#key_interna = f"{ip_dst_a[0]}.{ip_dst_a[1]}.0.0/16"
                        else: key_interna = result[0]

                        if key_interna in dns_match_ip:
                            if key in dns_match_ip[key_interna] and dns_match_ip[key_interna][key][RESPONSE] is None:
                                dns_match_ip[key_interna][key][RESPONSE] = 1
                                dns_match_ip[key_interna]["pairs_count"] += 1


fin.close()
f_resp.close()

last_hour = hour_to_timedelta(data[D_HORA])

with open(f"{VERSION}_{filename}_req_sem_resp.txt", "w") as f:
    for key in dns_match_total:
        dns = dns_match_total[key]
        
        #dns_count[TOTAL_REQ] += 1
        
        if not dns_req_eof(last_hour, dns[REQUEST_TIME], delta_seconds=2):
            #if dns[RESPONSE] is not None:
                #dns_count[TOTAL_PAIRS] += 1
            #else:
            if dns[RESPONSE] is None:
                print(dns[REQUEST], file=f)
                dns_count[WITHOUT_PAIR] += 1
        #else:
        elif dns[RESPONSE] is None: # esta no fim do arquivo e nao foi pareado
            dns_count[REQ_EOF] += 1

with open(f"{VERSION}_{filename}_estatisca_dns.txt", "w") as fout:
    print("QTD DE RESPONSES", dns_count[TOTAL_RESP], file=fout)
    print("QTD DE REQUESTS ", dns_count[TOTAL_REQ], file=fout)
    percent = (dns_count[TOTAL_PAIRS]/dns_count[TOTAL_REQ]) * 100
    print(f"\tQTD DE PARES(REQ,RESP): {dns_count[TOTAL_PAIRS]} ({percent:.2f}%)", file=fout)
    
    percent = (dns_count[WITHOUT_PAIR]/dns_count[TOTAL_REQ]) * 100
    print(f"\tQTD DE REQ SEM RESPOSTA: {dns_count[WITHOUT_PAIR]} ({percent:.2f}%)", file=fout)
    
    percent = (dns_count[REQ_EOF]/dns_count[TOTAL_REQ]) * 100
    print(f"\tQTD DE REQ NO FIM DO ARQUIVO(SEM RESPOSTA): {dns_count[REQ_EOF]} ({percent:.2f}%)", file=fout)

    percent = (dns_count[REPEATED_REQ]/dns_count[TOTAL_REQ]) * 100
    print(f"\tQTD DE REQ REPETIDAS: {dns_count[REPEATED_REQ]} ({percent:.2f}%)", file=fout)

    print(f"\n\tReq repetidas possuem chaves iguais\n\t\tchave = 'ip_src port_src ip_dst query_id query'", file=fout)

    print(f"\nCONVERSA ENTRE SERVIDORES DNS: {dns_count[CONV_ENTRE_SERVIDORES]}", file=fout)

with open(f"{VERSION}_{filename}_estatisca_dns_por_ip.txt", "w") as fout:
    for ip,dict_dns in dns_match_ip.items():
    #for ip,dict_dns in sorted(dns_match_ip.items(), key=lambda item: item[1]["req_count"], reverse= True):
        for key in dict_dns:
            dns = dict_dns[key]
            if not isinstance(dns, list): continue

            if not dns_req_eof(last_hour, dns[REQUEST_TIME], delta_seconds=2):
                if dns[RESPONSE] is None:
                    dict_dns["req_sem_resp_count"] += 1
            #else:
            elif dns[RESPONSE] is None: # esta no fim do arquivo e nao foi pareado
                dict_dns["req_eof_count"] += 1

    for ip,dict_dns in sorted(dns_match_ip.items(), key=lambda item: item[1]["req_sem_resp_count"], reverse= True):
        print(f"IP SRC: {ip}", file=fout)
        print(f"\tQTD DE REQUESTS: {dict_dns['req_count']}", file=fout)

        percent = (dict_dns["pairs_count"]/dict_dns["req_count"]) *100
        print(f"\tQTD DE PARES(REQ,RESP): {dict_dns['pairs_count']} ({percent:.2f}%)", file=fout)

        percent = (dict_dns["req_sem_resp_count"]/dict_dns["req_count"]) *100
        print(f"\tQTD DE REQ SEM RESPOSTA: {dict_dns['req_sem_resp_count']} ({percent:.2f}%)", file=fout)

        percent = (dict_dns["req_eof_count"]/dict_dns["req_count"]) *100
        print(f"\tQTD DE REQ EOF(SEM RESPOSTA): {dict_dns['req_eof_count']} ({percent:.2f}%)\n", file=fout)
