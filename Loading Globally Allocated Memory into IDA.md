# Loading Globally Allocated Memory into IDA

![GetLocalPlayer IDA Disassembler](http://i.imgur.com/VMGeDRm.png)

![Location of pWorld](http://i.imgur.com/lwvkV5x.png)

We want that memory!

> **Hold up!**  
  This instructional assumes that currently have loaded into IDA a PE Dump of the **currently running** executable, and that it is loaded (within IDA) at the same BASEADDRESS as the executable is currently running at. 
  
Since this is rather unlikely, you now have two choices.

  1. Start a new IDA project and load the dumped PE manually at the correct address
  2. [Rebase](https://www.hex-rays.com/products/ida/support/idadoc/1408.shtml) your existing project, and Reload the Input File with a new dump.

Please skip to the "Totally addicted to BASE" section to learn more. 
  
No really, go away.

If you're still reading, we'll assume you have a dumped copy of the (still running) executable loaded at the correct address in IDA.

So lets first find the GetLocalPlayer function we saw earlier.

```
0:  48 8b 05 e5 5b 9d 01    mov    rax, QWORD PTR [rip+0x19d5be5]
7:  48 8b 48 08             mov    rcx, QWORD PTR [rax+0x8]
b:  33 c0                   xor    eax, eax
d:  48 85 c9                test   rcx, rcx
10: 74 07                   je     0x19
12: 48 8b 81 88 10 00 00    mov    rax,QWORD PTR [rcx+0x1088]
19: c3                      ret
```

```
0:  48 8b 05 ?? ?? ?? ??    mov    rax, QWORD PTR [rip+????????]
7:  48 8b 48 ??             mov    rcx, QWORD PTR [rax+??]
b:  33 c0                   xor    eax, eax
d:  48 85 c9                test   rcx, rcx
10: 74 07                   je     0x19
12: 48 8b 81 ?? ?? ?? ??    mov    rax,QWORD PTR [rcx+????]
19: c3                      ret
```

Before we render it into a signature, lets look at the useful information we can get out of it:

```
48 8b 05 ?? ?? ?? ??  <-- Offset of *CWorld
48 8b 48 ??           <-- Offset of CPlayerPed in CWorld (0x08)
33 c0               
48 85 c9            
74 07               
48 8b 81 ?? ?? ?? ??  <-- Offset of CPlayerInfo in CWorld  (0x1088)
c3                  
```

And here is the final signature. `48 8b 05 ?? ?? ?? ?? 48 8b 48 ?? 33 c0 48 85 c9 74 07 48 8b 81 ?? ?? ?? ?? c3`

Lets write a little Python function to take full advantage of all that juicy information.

```py
def findGetLocalPlayer():
    findStart = LocByName("__ImageBase")
    foundEnd = 1<<63
    ea = FindBinary(findStart, 1, "48 8b 05 ?? ?? ?? ?? 48 8b 48 ?? 33 c0 48 85 c9 74 07 48 8b 81 ?? ?? ?? ?? c3")
    if not ea:
        raise Exception("Couldn't find GetLocalPlayer")
    result = dict(
            pWorld = Dword(ea + 3) + ea + ItemSize(ea),
            oCPlayerPed = Byte(ea + 0x0a),
            oCPlayerInfo = Dword(ea + 0x15),
            )
    MakeName(ea, "GetLocalPlayer")
    MakeFunction(ea, ea + 0x1a)
    print "Exe dump loaded at 0x%x" % findStart
    print "*CWorld is at 0x%x" % result['pWorld']
    print "CWorld is at 0x%x" % Qword(result['pWorld'])
    print "CWorld[%i][0x%x] is CPlayerInfo" % (result['oCPlayerPed'], result['oCPlayerInfo'])
    
findGetLocalPlayer()
```

Now paste all that into the Python prompt (that's in the Output Window), and hit Enter.

You should get something like this back:
```
Exe dump loaded at 0x7ff742550000
*CWorld is at 0x7ff7447dfa58
CWorld is at 0x1e6273bfa00
CWorld[8][0x1088] is CPlayerInfo
```

The reference to where you Exe dump is loaded (default is 0x14000000...) is important, because it's going to have to match up with the new memory dump we're about to make.

# Totally addicted to BASE
![Base Address in Task Explorer](http://i.imgur.com/CxhzQsM.png)  
*[Task Explorer](http://www.ntcore.com/files/ExplorerSuite.exe), part of Daniel Pistelli's excellent [Explorer Suite](http://www.ntcore.com/exsuite.php).*

![Base Address in IDA](http://i.imgur.com/Y41OLMV.png)  
*Our HEADER in IDA*

> **Note:** the matching base address, visible in both **Task Explorer** and **IDA**.  
`7ff742550000`
            
If those don't match, you're going to have to **Rebase**.  To produce the following graphics for this instructional tract, I had to reload, and my base address has also changed.  However, we're just going to go ahead and pretend it hasn't.

We're going to make two dumps.  One standard dump (Dump PE) of the executable, and one of the dynamically allocated memory we found before.

First, dump a copy of the executable.  We have to do this and the dynamic memory dump at the same time, or the two will not integrate correctly.  (It's a pointer thing).

![Dump PE](http://i.imgur.com/aBtBTQr.png)
![Name Dumped PE](http://i.imgur.com/ifgi256.png)

> **Note:** we are using the same careful file naming so there will be no mistakes later.

You can now return to the start of the tract, if you just needed to get a current dump.  Don't forgot ensure that you load this at the same address in IDA as it is in memory (that address is also in the filename, just in case you forget).

> **Note:** if you have CE handy, and are capable of determine the address of WorldPtr, you can continue without resorting to using IDA to determine the WorldPtr address.  (But you will have to do all that IDA stuff afterwards).

![Dumping Memory with Task manager](http://i.imgur.com/Ca4l0y3.png)
![Dumping Memory with Task manager](http://i.imgur.com/zdSl6gJ.png)
![Dumping Memory with Task manager](http://i.imgur.com/2BS38mn.png)


> **Note:** we include the offset of the memory dump in the file name, so we always know where to load it. 

![What, an error?!](http://i.imgur.com/8JoRwGb.png)

That's perfectly expected, don't worry.  It just means we asked for more memory than was available in that block.  The `.dmp` file we created has been created, and filled to maximum capacity. 

So back to IDA to load in our warez.

![Loading additional binary file in IDA](http://i.imgur.com/zWIhD1Q.png)
![Loading additional binary file in IDA #2](http://i.imgur.com/11sUT4t.png)
![Loading additional binary file in IDA #3](http://i.imgur.com/JIeK2Ds.png)

> **Note:** We copy the entire address of our dmp into the "Loading offset" input, prefaced by `0x`.  You can't see it all there in the screenshot, but trust me, it is.

After it's loaded, you'll want to make some tweaks to the new segment.  `Shift`+`F7` will bring up the Segment window, right click and edit seg000, and change a few things so it looks like this:

![Segment settings](http://i.imgur.com/TA35ntN.png)

Mainly, you want the class to be `DATA` the bitness to be `64-bit`.

Now if your dumped PE image is correct and in the right place, you can test out the functionality using this little script.

If it fails, you did something wrong, and you are proably too stupid to be a reverse engineer.  (A)bort (R)etry (I)gnore.

```py
def findNativeRegistrationTable():
    findStart = LocByName("__ImageBase")
    foundEnd = 1<<63
    ea = FindBinary(findStart, 1, "76 61 49 8B 7A 40 48 8D 0D")
    if ea:
        ea += 6
        tablePtr = ea + Dword(ea + 3) + 7
        print "0x%x" % tablePtr
        MakeName(tablePtr, "NativeRegistrationTable")
        Jump(tablePtr)
        return tablePtr
    else:
        print "No tablePtr"
        return None


def makeBucketList(nextStruct):
    totalCount = 0
    nativeFunctions = []
    while nextStruct:
        if not MakeStruct(nextStruct, "NativeRegistration"):
            MakeUnknown(ItemHead(nextStruct), nextStruct - ItemHead(nextStruct) + 0, 1)
            if not MakeStruct(nextStruct, "NativeRegistration"):
                print "Failed to convert location %012x into NativeRegistration" % nextStruct
                break
        count = Byte(nextStruct+8*8)
        for i in xrange(1, count + 1):
            ptr = nextStruct + 8 * i
            ea = Qword(ptr)
            name = Name(ea)
            hash = "%016x" % (Qword(ptr + 64))
            nativeFunctions.append([name, ea, hash])
        nextStruct = Qword(nextStruct)

    return nativeFunctions

def processBucketLists(ea, count = 256):
    totalCount = 0
    nativeFunctions = []
    for i in xrange(count):
        nextStruct = Qword(ea + i * 8)
        if not nextStruct:
            print "No more buckets to make at count %i" % count
            break
        nativeFunctions.extend(makeBucketList(nextStruct))

    print "Found %i native functions" % nativeFunctions.__len__()
    return nativeFunctions

print processBucketLists(findNativeRegistrationTable())
```