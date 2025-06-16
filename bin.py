import math
def toNegative(num):
   list = [1,1,1,1,1,1,1,1]
   makeIt = [0,0,0,0,0,0,0,1]
   checking = 128
   n = 0 
   for i in range(len(list)):
        if(num >= checking):
            list[i] = 0
            num -= checking
        checking = math.sqrt(checking)
    
   for i in range(len(list)):
       if(list[i] == 0 & makeit[i] ==1 | list[i] == 1 & makeIt[i] == 0):
           list[i] = 1
       elif(list[i] == 1 & makeIt[i] == 1):
           list[i] = 0
           num = 1
       else:
           list[i] = 0 + num
           num = 0
   return list


