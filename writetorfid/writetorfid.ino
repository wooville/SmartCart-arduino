#include <SPI.h>      //include the SPI bus library
#include <MFRC522.h>  //include the RFID reader library

#define SS_PIN 53  //slave select pin
#define RST_PIN 5  //reset pin

MFRC522 rfid(SS_PIN, RST_PIN);  // instatiate a MFRC522 reader object.
MFRC522::MIFARE_Key key;          //create a MIFARE_Key struct named 'key', which will hold the card information

//this is the block number to write to
int block=2;  

byte blockToWrite[16] = {10};  // value to write into block
byte blockToRead[18];

void setup() 
{
  Serial.begin(9600);        // Initialize serial communications with the PC
  SPI.begin();               // Init SPI bus
  rfid.PCD_Init();           // Init MFRC522 
  Serial.println("Scan a MIFARE Classic card");
  
  // prepare key for read/write
  for (byte i = 0; i < 6; i++) {
    key.keyByte[i] = 0xFF;
  }
}

void loop()
{  
  // look for cards
  if ( ! rfid.PICC_IsNewCardPresent()) {
    return;
  }
  
  // read card if there is one
  if ( ! rfid.PICC_ReadCardSerial()) 
  {
    return;
  }

  // write to specified block number of card with data
  writeBlock(block, blockToWrite);
  
  // read the block and print contents
  readBlock(block, blockToRead);
  Serial.print("read block: ");
  for (int j=0 ; j<16 ; j++)
  {
    Serial.write (blockToRead[j]);
  }
  Serial.println("");
}



// write data to specified block number    
int writeBlock(int blockNumber, byte arrayAddress[]) 
{
  // determine trailer block for the sector (every 4th block)
  int blockSectorStart=blockNumber/4*4;
  int trailerBlock=BlockSectorStart+3;

  // confirm that we aren't writing into a trailer
  if (blockNumber > 2 && (blockNumber+1)%4 == 0){
    Serial.print(blockNumber);
    Serial.println(" is a trailer block:");
    return -1;
  }
  
  Serial.print(blockNumber);
  Serial.println(" is a data block:");
  
  // authenticate block
  byte status = rfid.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, trailerBlock, &key, &(rfid.uid));

  if (status != MFRC522::STATUS_OK) {
    Serial.print("Failed to authenticate: ");
    Serial.println(rfid.GetStatusCodeName(status));
    return -1;
  }
  
  // write to the block 
  status = rfid.MIFARE_Write(blockNumber, arrayAddress, 16);

  if (status != MFRC522::STATUS_OK) {
    Serial.print("MIFARE_Write() failed: ");
    Serial.println(rfid.GetStatusCodeName(status));
    return -1;
  }

  Serial.println("wrote to block");
}


int readBlock(int blockNumber, byte arrayAddress[]) 
{
  // determine trailer block for the sector
  int blockSectorStart=blockNumber/4*4;
  int trailerBlock=BlockSectorStart+3;

  // authenticate block
  byte status = rfid.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, trailerBlock, &key, &(rfid.uid));

  if (status != MFRC522::STATUS_OK) {
    Serial.print("Failed to authenticate: ");
    Serial.println(rfid.GetStatusCodeName(status));
    return -1;
  }
  
  // reading a block
  byte buffersize = 18;
  status = rfid.MIFARE_Read(blockNumber, arrayAddress, &buffersize); // MIFARE_Read function wants a pointer to buffersize
  if (status != MFRC522::STATUS_OK) {
    Serial.print("Read failed: ");
    Serial.println(rfid.GetStatusCodeName(status));
    return -1;
  }
  Serial.println("Block " + blockNumber + " read successfully");
}
