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
        checking = math.pow(2, 7-i)
   list[0] = 1
   for i in range(len(list) +1, 1):
       if(list[i] == 0 and makeit[i] ==1 or list[i] == 1 and makeIt[i] == 0):
           list[i] = 1
       elif(list[i] == 1 and makeIt[i] == 1):
           list[i] = 0
           num = 1
       else:
           list[i] = 0 + num
           num = 0
   return list


