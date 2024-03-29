CREATE TABLE captured_packet
(ID SERIAL PRIMARY KEY     NOT NULL, 
PACKET_ID INT NOT NULL,
SID INT NOT NULL,
CAPTURED_TIME  TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
MSG TEXT NOT NULL, 
PACKET TEXT NOT NULL, 
SEEN BOOLEAN NOT NULL DEFAULT FALSE);