from pysake.constants import LOGGER_NAME
import logging

class Peer():

    """
    Abstract class for Server / Client to keep track of the current stage.
    """

    _stage:int = 0
    log = logging.getLogger(LOGGER_NAME).getChild("Peer")

    def __init__(self):
        pass

    def increment_stage(self):
        new = self._stage + 1
        self.log.info(f"Advancing from SAKE handshake stage {self._stage} to {new}")
        self._stage = new
        self.log.debug(f"state = {str(self.session)}")
        return
    
    def get_stage(self) -> int: 
        return self._stage
    
    def _brute_force_ghost_byte(self, crypt_obj, payload16, expected:int):
      
        # NOTE: i think the used padding at the last permit message is a random byte in the original implementations.
        # this presents a challenge for us when we are trying to test our code against real world traffic
        # we can brute force it really quickly, then if the calculated cmac matches, we should be good to go (?)
       
        found = []
        for i in range(0, 0xff):
            pad = bytearray([i])
            test = payload16 + pad
            bak_seq = crypt_obj.tx_seq
          #  try:
            out = crypt_obj.encrypt(test)
          #  except Exception as e:
                #print(e)
          #      crypt_obj.seq = bak_seq
          #      continue
            crypt_obj.tx_seq = bak_seq
            if out[-4] == expected:
                found.append(i)
                self.log.debug(f"found a ghost byte: {hex(i)}")
        if len(found) != 1:
            raise Exception(f"Did not get exactly 1 ghost byte! len={len(found)}")
        return found[0]
