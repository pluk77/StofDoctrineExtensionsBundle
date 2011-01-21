<?php

namespace Stof\DoctrineExtensionsBundle;

use Gedmo\Translatable\TranslationListener as BaseTranslationListener;

/**
 * TranslationListener
 *
 * @author Christophe COEVOET
 */
class TranslationListener extends BaseTranslationListener
{
    protected $_defaultTranslationEntity = 'Stof\DoctrineExtensionsBundle\Entity\Translation';
}
