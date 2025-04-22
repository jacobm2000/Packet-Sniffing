
from liveSniffer import runLiveSniff
from batchSniff import runBatchSniff
from sharedFunctions import twoValueInput
import os




#keep Track of wheather or not it has recived a valid choice fromt he user

def snifferMain():

    choice=twoValueInput("Please type 1 for Live Sniffing or type 2 for Batch Sniffing\n ",
                             "Invalid input. Please either 1 or 2.",'1','2')
    if(choice.strip()=="1"):
        print("Live sniffing selected:\n")
        runLiveSniff()
        gettingInput=False
    elif(choice.strip()=="2"):
        print("Batch sniffing selected \n")
        runBatchSniff()
        gettingInput=False
    else:
        print("Invalid input \n")
if __name__ == "__main__":
    os.makedirs("summaries", exist_ok=True)
    os.makedirs("pcaps", exist_ok=True)
    snifferMain()