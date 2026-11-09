<?php
// LAB-ONLY POP gadget for Category B.
// The real target class here is Monolog (see composer.json); this stand-in
// exists so the handler-mismatch -> object-injection -> RCE path can be
// proven end-to-end without phpggc. __destruct fires when the object is
// freed at request shutdown, which is exactly the primitive phpggc abuses.
class LabGadget
{
    public $cmd = "id";

    public function __destruct()
    {
        if (is_string($this->cmd) && $this->cmd !== "") {
            echo "\n[GADGET] __destruct fired: ";
            system($this->cmd);
            echo "\n";
        }
    }
}
