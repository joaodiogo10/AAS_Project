import numpy as np
import matplotlib.pyplot as plt
import csv
import numpy as np
import argparse

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('-i', '--input', nargs='?',required=True, help='input file')
    parser.add_argument('-o', '--output', nargs='?',required=False, help='output file')
    
    args=parser.parse_args()
    
    file_input=args.input
    if args.output is None:
        tmp=str.split(file_input, ".")[0]
        file_output=tmp
    else:
        file_output=args.output

    with open(file_input,'r') as dest_f:
        iter = csv.reader(dest_f, delimiter = ",")
        next(iter, None)  # skip the header
        data = [data for data in iter]

    np_data = np.asarray(data, dtype = float)

    line1 = plt.plot(np_data[:,0])
    plt.setp(line1, label = "authentication", linestyle='-')

    line2 = plt.plot(np_data[:,1], )
    plt.setp(line2, label = "association",linestyle='-')

    line3 = plt.plot(np_data[:,2], label = "eapol_first")
    plt.setp(line3, label = "eapol first",linestyle='-')

    line4 = plt.plot(np_data[:,3], label = "eapol_second")
    plt.setp(line4, label = "eapol second",linestyle='-')

    plt.legend()
    plt.title("Association transaction request/reponse interval")
    plt.xlabel("Sample number")
    plt.ylabel("Time interval (us)")
    plt.savefig(file_output)
        
    plt.show()


if __name__ == '__main__':
    main()
