
from liveSniffer import runLiveSniff
from batchSniff import runBatchSniff
import os



#keep Track of wheather or not it has recived a valid choice fromt he user

def snifferMain():
    gettingInput=True
    while (gettingInput):
        choice=input("Please type 1 to select live sniffing or 2 to select batch sniffing:\n")
        if(choice.strip()=="1"):
          print("Active sniffing selected:\n")
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