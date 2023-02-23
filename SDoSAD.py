import pandas as pd
import argparse
import statistics

def parse_args():

    # Parsing CLI arguments
	sample = "Sample: python3 slow_ddos_detector.py [-f file.csv -l limits] or [-b file]"
	parser = argparse.ArgumentParser(description='Slow DDoS Detection. \nSend a file with TSP \
    	stream and limits to find addresses from which slow DDoS attacks were performed or send \
    	a file with normal traffic to get a file with limit values', epilog=sample)

	parser.add_argument("-f", "--file", help=".csv file", required=False)
	parser.add_argument("-l", "--limits", help=".csv file", required=False)
	parser.add_argument("-b", "--benign", help=".csv file", required=False) 
	parser.add_argument("-i", "--info", help="additional information for malicious ip", action='store_true', required=False) 
	args = parser.parse_args()

    return args

def read_csv(csv_file, required_columns):

	pd_file = pd.read_csv(csv_file, usecols = required_columns)

	return pd_file

def to_float(field):

	if (field == 'nan'):  
		return 0.0
	x = float(field)
	if x in [float("-inf"),float("inf")]: return 0.0

	return x

def limit_coef_of_variation(coef_variation):
	coefs = []
	for i in range(2):
		min_coef = min(coef_variation)
		coefs.append(min_coef)
		coef_variation.remove(min_coef)

	return statistics.mean(coefs)


def set_limits(traffic):
	traffic = traffic.fillna(0)
	i = 0
	connection_per_minute = 60

	last_connect = {}
	one_minute_connection = {}
	ip_flow_b_s = {}
	ip_duration = {}

	coef_variation = []
	deviation_duration = []
	flow_duration = []
	flow_pkts_s = []
	flow_byts_s = []
	fwd_pkts_s = []
	bwd_pkts_s = []
	found_ip = []
	count_of_connections = []

	count_rows = len(traffic) - 1
	
	while(i < count_rows):

#Закоментувати цю умову при роботі з реальним трафіком
		if (traffic.loc[i, 'label'] != "BENIGN"):
			i += 1
			continue

		duration = to_float(traffic.loc[i, 'Flow.Duration'])
		flow_duration.append(duration)

		flow_p_s = to_float(traffic.loc[i, 'Flow.Pkts.s'])
		flow_pkts_s.append(flow_p_s)

		flow_b_s = to_float(traffic.loc[i, 'Flow.Byts.s'])
		flow_byts_s.append(flow_b_s)

		fwd_p_s = to_float(traffic.loc[i, 'Fwd.Pkts.s'])
		fwd_pkts_s.append(fwd_p_s)

		bwd_p_s = to_float(traffic.loc[i, 'Bwd.Pkts.s'])
		bwd_pkts_s.append(bwd_p_s)


		ip = traffic.loc[i, 'Ip.src']

		if ip in found_ip: 	
			
			ip_flow_b_s[ip].append(to_float(traffic.loc[i, 'Flow.Byts.s']))

			#ip_duration[ip].append(to_float(traffic.loc[i, 'Flow.Duration']))

		else:
			found_ip.append(ip)
			
			ip_flow_b_s[ip] = []
			ip_flow_b_s[ip].append(to_float(traffic.loc[i, 'Flow.Byts.s']))

			#ip_duration[ip] = []
			#ip_duration[ip].append(to_float(traffic.loc[i, 'Flow.Duration']))


		if ip in last_connect:
			if(last_connect[ip] == str(traffic.loc[i, 'Date.time'])):
				one_minute_connection[ip] += 1
			else:
				last_connect[ip] = str(traffic.loc[i, 'Date.time'])
				if(one_minute_connection[ip] > connection_per_minute):
					count_of_connections.append(one_minute_connection[ip])
				one_minute_connection[ip] = 1
		else:
			one_minute_connection[ip] = 1
			last_connect[ip] = str(traffic.loc[i, 'Date.time'])

		i += 1

	for ip in found_ip:
		if(len(ip_flow_b_s[ip]) > connection_per_minute):	
			dev = statistics.stdev(ip_flow_b_s[ip])
			mean = statistics.mean(ip_flow_b_s[ip])
			if(mean > 0):
				coef_variation.append(dev/mean)



	limits_str = "Flow.Duration.std,Flow.Pkts.s.std,Flow.Byts.s.std,Fwd.Pkts.s.std,Bwd.Pkts.s.std,Connection.threshold,Deviation.Flow.Byts.s.min\n"
	limits_str += str(statistics.mean(flow_duration)) + "," + str(statistics.median(flow_pkts_s)) + ","
	limits_str += str(statistics.median(flow_byts_s)) + "," + str(statistics.median(fwd_pkts_s)) + "," 
	limits_str += str(statistics.median(bwd_pkts_s)) + "," + str(round(statistics.mean(count_of_connections))) + "," + str(limit_coef_of_variation(coef_variation)) # минуле занчення str(min(coef_variation)

	with open('limits.csv', 'w') as file:
		file.write(limits_str)

	return limits_str

def traffic_analyzer(traffic, limits, info = False):

	one_minute_connection = {}
	count_connect_ip = {}
	last_connect = {}

	ip_flow_b_s = {}
	ip_duration = {}
	ip_deviation_flow_b_s = {}
	ip_deviation_duration = {}

	traffic = traffic.fillna(0)
	std_flow_duration = to_float(limits.loc[0, 'Flow.Duration.std'])
	std_flow_pkts_s = to_float(limits.loc[0, 'Flow.Pkts.s.std'])
	std_flow_byts_s = to_float(limits.loc[0, 'Flow.Byts.s.std'])
	std_fwd_pkts_s = to_float(limits.loc[0, 'Fwd.Pkts.s.std'])
	std_bwd_pkts_s = to_float(limits.loc[0, 'Bwd.Pkts.s.std'])
	connection_threshold = round(limits.loc[0, 'Connection.threshold'])
	deviation_flow_b_s = to_float(limits.loc[0, 'Deviation.Flow.Byts.s.min'])
	deviation_duration = 0.34


	i = 0
	count_rows = len(traffic) - 1
	while(i < count_rows):

		ip = traffic.loc[i, 'Ip.src']
		is_attaker = 0
		is_suspicious_duration = 0

		if (to_float(traffic.loc[i, 'Flow.Duration']) > std_flow_duration):
			is_suspicious_duration = 1

		if(to_float(traffic.loc[i, 'Flow.Pkts.s']) < std_flow_pkts_s):
			is_attaker += 1

		if(to_float(traffic.loc[i, 'Flow.Byts.s']) < std_flow_byts_s):
			is_attaker += 1

		if(to_float(traffic.loc[i, 'Fwd.Pkts.s']) < std_fwd_pkts_s):
			is_attaker += 1

		if(to_float(traffic.loc[i, 'Bwd.Pkts.s']) < std_bwd_pkts_s):
			is_attaker += 1

		if(to_float(traffic.loc[i, 'Bwd.IAT.Min']) == 0.0):
			is_attaker += 1

		if((is_suspicious_duration == 1) & (is_attaker > 3)): 						#Якщо задовільняє встановленим границям

			if ip in last_connect: 													#Якщо адресу вже було відмічено як підозрілу
				
				ip_flow_b_s[ip].append(to_float(traffic.loc[i, 'Flow.Byts.s']))

				ip_duration[ip].append(to_float(traffic.loc[i, 'Flow.Duration']))

				if(last_connect[ip] == str(traffic.loc[i, 'Date.time'])):			#Якщо попереднє підключення з цієї адреси віддулось в цю ж хвилину
					one_minute_connection[ip][1] += 1								#Додати до кількості підключень з цієї адрес в ту саму хвилину +1
					count_of_connections = one_minute_connection[ip][1]				#Кількість підключень за цю хвилину на цей момент	

					if(count_of_connections >= connection_threshold):				#Якщо кількість підключень за хв >= границі підключень за хв

						if((ip in count_connect_ip) == False):						#Якщо адреса до цього не була підозріою
							count_connect_ip[ip] = []								#Додати запис про адресу

						if(count_of_connections == connection_threshold):			#Якщо кількість підключень в цю хвилину дорівнює порогу підключень
							count_connect_ip[ip].append(connection_threshold)		#Додати до адреси кількість підключень
							one_minute_connection[ip][0] += 1						

						else:
							count_connect_ip[ip][one_minute_connection[ip][0]] += 1
				else:
					last_connect[ip] = str(traffic.loc[i, 'Date.time'])
					one_minute_connection[ip][1] = 0
			else:
				one_minute_connection[ip] = [-1,0] #[minute, count_of_conections]
				last_connect[ip] = str(traffic.loc[i, 'Date.time'])

				
				ip_flow_b_s[ip] = []
				ip_flow_b_s[ip].append(to_float(traffic.loc[i, 'Flow.Byts.s']))

				ip_duration[ip] = []
				ip_duration[ip].append(to_float(traffic.loc[i, 'Flow.Duration']))

		i += 1

	for ip in count_connect_ip:
			ip_deviation_flow_b_s[ip] = statistics.stdev(ip_flow_b_s[ip])/statistics.mean(ip_flow_b_s[ip])
			ip_deviation_duration[ip] = statistics.stdev(ip_duration[ip])/statistics.mean(ip_duration[ip])

	if(info == True):
		malicious_ip_info_str = ""
		for ip in ip_deviation_flow_b_s:
			if((ip_deviation_flow_b_s[ip] < deviation_flow_b_s) & (ip_deviation_duration[ip] < deviation_duration)):
				malicious_ip_info_str += "\nIp addresse: " + str(ip) + "\nMax connection per minute: " + str(max(count_connect_ip[ip])) \
				+ "\nCoef of variation for duration: " + str(ip_deviation_duration[ip]) + "\nCoef of variation for flow bytes/s: "+ \
				str(ip_deviation_flow_b_s[ip]) + "\n"
		
		return malicious_ip_info_str 

	else:
		malicious_ip = []
		for ip in ip_deviation_flow_b_s:
			if((ip_deviation_flow_b_s[ip] < deviation_flow_b_s) & (ip_deviation_duration[ip] < deviation_duration)):
				malicious_ip.append(ip)
		return malicious_ip

if __name__ == "__main__":

    required_columns = ["Ip.src", "Port.src","Ip.dst","Port.dst", "Date.time", "Flow.Duration", \
    "Flow.Pkts.s", "Flow.Byts.s", "Fwd.Pkts.s", "Bwd.Pkts.s", 'Bwd.IAT.Min', 'Fwd.IAT.Min', "label"]

    standart_columns = ["Flow.Duration.std", "Flow.Pkts.s.std", "Flow.Byts.s.std", "Fwd.Pkts.s.std", \
    "Bwd.Pkts.s.std", "Connection.threshold", "Deviation.Flow.Byts.s.min"]
    
    args = parse_args()

    if((args.file != None) & (args.limits != None) & (args.benign == None)):
    	traffic = read_csv(args.file, required_columns)
    	limits = read_csv('limits.csv', standart_columns)
    	if(args.info == True):
    		malicious_ip = traffic_analyzer(traffic, limits, True)
	    	print(malicious_ip)
    	else:
	    	malicious_ip = traffic_analyzer(traffic, limits)
	    	print("Malicious ip:\n")
	    	print(malicious_ip)

    elif((args.benign != None) & (args.file == None) & (args.limits == None)):
    	traffic = read_csv(args.benign, required_columns)
    	limits_str = set_limits(traffic)
    	print("limits.csv:\n")
    	print(limits_str)
    else:
    	print("Please specify the file with the traffic you want to check and limits or the file with normal \
    		traffic in the format:\n python3 slow_ddos_detector.py [-f file.csv -l limits] or [-b file]")
    	print(args)