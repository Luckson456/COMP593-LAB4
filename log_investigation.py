"""
Description:
 Generates various reports from a gateway log file.

Usage:
 python log_investigation.py log_path

Parameters:
 log_path = Path of the gateway log file
"""
import log_analysis_lib
import csv
import re
from datetime import datetime

# Get the log file path from the command line
# Because this is outside of any function, log_path is a global variable
log_path = log_analysis_lib.get_file_path_from_cmd_line()

def main():
    # Determine how much traffic is on each port
    port_traffic = tally_port_traffic()

    # Per step 9, generate reports for ports that have 100 or more records
    for port, count in port_traffic.items():
        if count >= 100:
            generate_port_traffic_report(port)

    # Generate report of invalid user login attempts
    generate_invalid_user_report()

    # Generate log of records from source IP 220.195.35.40
    generate_source_ip_log('220.195.35.40')

def tally_port_traffic(log_path,regex_pattern):
    """Produces a dictionary of destination port numbers (key) that appear in a 
    specified log file and a count of how many times they appear (value)

    Returns:
        dict: Dictionary of destination port number counts
    """
    # TODO: Complete function body per step 7
    port_traffic={}
    extracted_data=[]
    with open (log_path,'r' )as log_file:
        for line in log_file:
            match=re.search(regex_pattern,line)
            if match:
                extracted_values=match.groups()
                extracted_data.append(extracted_values)
                port=int(extracted_values[-1])
                port_traffic[port]=port_traffic.get(port,0)+1
                            
    return {port_traffic,extracted_data}

def generate_port_traffic_report(log_path ,port_number):
    """Produces a CSV report of all network traffic in a log file for a specified 
    destination port number.

    Args:
        port_number (str or int): Destination port number
    """
    
    # TODO: Complete function body per step 8
    regex_pattern =r'SRC=(.*?) DST=(.*?)LEN=(.*?)'
    extracted_data =[]
    
    with open(log_path,'r') as log_file:
        for line  in log_file:
            match= re.search(regex_pattern,line)
            if match:
                src,dst,length =match.groups()
                dst_port=int(dst.split('.')[-1])
                if dst_port==int(port_number):
                    extracted_data.append((src,dst,length))
                    
    if extracted_data:
        report_path=f'port_{port_number}_traffic_report.csv'
        with open(report_path,'w',newline='') as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(['Source IP','Destination IP',length])
            writer.writerows(extracted_data)
        
    # Get data from records that contain the specified destination port
    # Generate the CSV report
    return

def generate_invalid_user_report(log_path,regex_pattern):
    """Produces a CSV report of all network traffic in a log file that show
    an attempt to login as an invalid user.
    """
    # TODO: Complete function body per step 10
    extracted_data=[]
    
    with open(log_path,'r')as log_file:
        for line in log_file:
            match=re.search(regex_pattern,line)
            if match:
                src, dst,user=match.groups()
                if user.lower()=='invalid':
                    extracted_data.append((src,dst,user))
                    
    if extracted_data:
        report_path='invalid_user_login_report.csv'
        with open(report_path,'w',newline='')as csv_file:
            writer=csv.writer(csv_file)
            writer.writerow(['Source IP','Destination IP','Username'])
            writer.writerows(extracted_data)
    # Get data from records that show attempted invalid user login
    # Generate the CSV report
    return

def generate_source_ip_log(log_path,ip_address,output_file):
    """Produces a plain text .log file containing all records from a source log
    file that contain a specified source IP address.

    Args:
        ip_address (str): Source IP address
    """
    # TODO: Complete function body per step 11
    extracted_data=[]
    
    with open(log_path,'r') as log_file:
        for line in log_file:
            if ip_address in line:
                extracted_data.append(line.strip())
                
    if extracted_data:
        with open(output_file,'w')as output_log:
            output_log.write('\n'.join(extracted_data))
    # Get all records that have the specified source IP address
    # Save all records to a plain text .log file
    return

if __name__ == '__main__':
    main()