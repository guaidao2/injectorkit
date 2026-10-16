<?php
// A cache entry, of the kind a framework hands a phar metadata blob to work
// with. `__destruct` runs when PHP releases the object, and that is where a real
// gadget chain hangs off. This one writes the file the object was told to write,
// so the lab can show the difference between "the archive was opened" and "the
// metadata was unserialized and did something".

declare(strict_types=1);

final class Cache
{
    public string $key = '';
    public string $path = '';

    public function __destruct()
    {
        if ($this->path !== '') {
            @file_put_contents($this->path, "gadget ran: {$this->key}\n");
        }
    }
}
