def readfile(filename):
    stream = open(filename,'r')
    filetext = stream.read()
    stream.close()
    return filetext


def writefile(filename, text):
    stream = open(filename, 'w')
    stream.write(text)
    stream.close()
    return


text = readfile("test.txt")
print(text)
writefile("testpaste.txt", text)