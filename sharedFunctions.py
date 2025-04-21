# This function uses a loop to ensure that the user inputs the proper value for a 2 value and return an error if neither values are present
def twoValueInput(prompt, error, value1, value2):
    
    while(True):
        getInput=input(str(prompt)).strip().lower()
        if getInput==value1 or getInput==value2:
            return getInput
        else:
            print(str(error))
    