<?php

namespace Kubio\Blocks;

use Kubio\Core\Registry;

class ButtonBlock extends LinkBlock{}

Registry::registerBlock( __DIR__, ButtonBlock::class );
