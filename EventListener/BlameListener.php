<?php

namespace Stof\DoctrineExtensionsBundle\EventListener;

use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Role\SwitchUserRole;
use Symfony\Component\Security\Core\SecurityContextInterface;

use Gedmo\Blameable\BlameableListener;

/**
 * BlameableListener
 *
 * @author David Buchmann <mail@davidbu.ch>
 */
class BlameListener implements EventSubscriberInterface
{
    /**
     * @var SecurityContextInterface
     */
    private $securityContext;

    /**
     * @var BlameableListener
     */
    private $blameableListener;

    /**
     * @var EntityManagerInterface
     */
    private $entityManager;

    public function __construct(
        BlameableListener $blameableListener,
        SecurityContextInterface $securityContext = null,
        $entityManager
    ) {
        $this->blameableListener = $blameableListener;
        $this->securityContext = $securityContext;
        $this->entityManager = $entityManager;
    }

    /**
     * Set the username from the security context by listening on core.request
     *
     * @param GetResponseEvent $event
     */
    public function onKernelRequest(GetResponseEvent $event)
    {
        if (null === $this->securityContext) {
            return;
        }

        $token = $this->securityContext->getToken();

        if (null !== $token && $this->securityContext->isGranted('IS_AUTHENTICATED_REMEMBERED')) {

            // if entity manager exists, then can check for original token (impersonate)
            if ($this->entityManager instanceof EntityManagerInterface) {

                $originalToken = $this->getOriginalToken($token);

                if ($originalToken instanceof TokenInterface) {
                    $user = $this->entityManager->merge($originalToken->getUser());
                    $this->blameableListener->setUserValue($user);
                } else {
                    $this->blameableListener->setUserValue($token->getUser());
                }
            } else {
                $this->blameableListener->setUserValue($token->getUser());
            }
        }
    }

    public static function getSubscribedEvents()
    {
        return array(
            KernelEvents::REQUEST => 'onKernelRequest',
        );
    }

    /**
     * Gets the original Token from a switched one.
     *
     * @param TokenInterface $token A switched TokenInterface instance
     *
     * @return TokenInterface|false The original TokenInterface instance, false if the current TokenInterface is not switched
     */
    private function getOriginalToken(TokenInterface $token)
    {
        foreach ($token->getRoles() as $role) {
            if ($role instanceof SwitchUserRole) {
                return $role->getSource();
            }
        }

        return false;
    }
}
