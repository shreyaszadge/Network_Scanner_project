#[+]installation module
#[+]developer:-shreyas zadge
#[+]script_version:-1.0
import scapy.all as scapys
import optparse
from mac_vendor_lookup import MacLookup



#[+] check mac_address vender
def maclookup(mac):
    return MacLookup().lookup(mac)
#[+]main program which give info about connecting devices in your network
def scan(ip):
    arp_request=scapys.ARP(pdst=ip)
    boadcast=scapys.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_request_boardcast=boadcast/arp_request
    ans_list=scapys.srp(arp_request_boardcast,verbose=False,timeout=1)[0]
    return ans_list
#[+]getting scanning ip from outside  
def optp():
     parser1 = optparse.OptionParser()
     parser1.add_option("-t","--target",dest="IP",help="write down ip address")  
     (options,aruguments)=parser1.parse_args() 
     return options
#[+]network scanning information convert to dictionary    
def results_dict(ans_list):
    results_dict=[]
    for items in ans_list:
        results_dict.append(items)
    return results_dict
#[+]network scanning info printing into beatuiful table 
def printing_beautifully(list_dict):
    
    print("IP"+"\t\t\t"+"MAC ADDRESS"+"\t\t"+"COMPANY MAC"+"\n-------------------------------------------")
    for items in list_dict:
        mac_add =maclookup(items[1].hwsrc)
        print(items[1].psrc+"\t"+">>>>"+items[1].hwsrc+"\t"+mac_add)    

#[+]Main program
if __name__ =="__main__":
    option=optp()
    ans_list=scan(option.IP)
    ans_dict=results_dict(ans_list)
    printing_beautifully(ans_dict)
    

