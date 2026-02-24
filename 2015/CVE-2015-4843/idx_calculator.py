def main():
        overflow = -294967276
        lenRealClassArray = 125000000*4         


        dst = int(input("Address of dst: "))
        realClassArray = int(input("Address of realClassArray: "))

        realClassArray_end = realClassArray + lenRealClassArray

        oop = dst + overflow; 

        print("Address of OOP = " + str(oop))

        if oop < realClassArray or oop > realClassArray_end:
            print("OOP is not inside realClassArray :(")
        else:
            idx = int(((oop - realClassArray) -16) / 4)
            print("realClassArray[idx] = " + str(idx))

if __name__ == "__main__":
    main()
