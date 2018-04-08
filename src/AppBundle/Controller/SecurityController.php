<?php

namespace AppBundle\Controller;


use AppBundle\Entity\User;
use AppBundle\Form\GoogleSignUpType;
use AppBundle\Form\SignUpType;
use AppBundle\Service\OpenIdConnectService;
use AppBundle\Service\Utilities\UriSafeBase64Service;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Encoder\UserPasswordEncoderInterface;
use Symfony\Component\Security\Csrf\TokenGenerator\UriSafeTokenGenerator;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;

class SecurityController extends Controller
{
    private $openIdConnectService;
    private $uriSafeBase64Service;

    public function __construct(OpenIdConnectService $openIdConnectService, UriSafeBase64Service $uriSafeBase64Service)
    {
        $this->openIdConnectService = $openIdConnectService;
        $this->uriSafeBase64Service = $uriSafeBase64Service;
    }

    public function signUpAction(Request $request, UserPasswordEncoderInterface $passwordEncoder)
    {
        $user = new User();
        $form = $this->createForm(SignUpType::class, $user);

        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            $password = $passwordEncoder->encodePassword($user, $user->getPlainPassword());
            $user->setPassword($password);

            $entityManager = $this->getDoctrine()->getManager();
            $entityManager->persist($user);
            $entityManager->flush();

            return $this->redirectToRoute('homepage');
        }

        return $this->render('security/sign_up.html.twig', array(
            'form' => $form->createView()
        ));
    }

    public function loginAction(Request $request, AuthenticationUtils $authenticationUtils)
    {
        $error = $authenticationUtils->getLastAuthenticationError();

        $lastUserName = $authenticationUtils->getLastUsername();

        return $this->render('security/login.html.twig', array(
            'last_username' => $lastUserName,
            'error' => $error
        ));
    }

    public function googleLoginAction(Request $request)
    {
        $session = $request->getSession();

        $uriSafeTokenGenerator = new UriSafeTokenGenerator();
        $state = $uriSafeTokenGenerator->generateToken();
        $session->set('state', $state);

        $url = "https://accounts.google.com/o/oauth2/v2/auth?"
            . "client_id=xxxxxx.apps.googleusercontent.com&"
            . "response_type=code&"
            . "scope=openid%20email&"
            . "redirect_uri=http://localhost/app_dev.php/google&"
            . "state=$state&"
            . "prompt=select_account&"
            . "nonce=0394852-3190485-2490358&";

        return $this->redirect($url);
    }

    public function redirectGoogleLoginAction(Request $request)
    {
        // loginするため
        if ($request->query->get('state') != $request->getSession()->get('state')) {
            return new Response('Invalid state parameter', 401);
        }

        $token = $this->openIdConnectService->getToken($request->query->get('code'));

        list($headerBase64, $payloadBase64, $signatureBase64) = explode(".", $token['id_token']);

        $header = json_decode($this->uriSafeBase64Service->decode($headerBase64), true);

        $certificates = $this->openIdConnectService->getCerts();

        $kid = $header['kid'];
        $certificate = $certificates[$kid];
        $success = openssl_verify("$headerBase64.$payloadBase64", $this->uriSafeBase64Service->decode($signatureBase64), $certificate, OPENSSL_ALGO_SHA256);

        if ($success === 1) {
            $payloadJson = json_decode($this->uriSafeBase64Service->decode($payloadBase64), true);
        } elseif ($success === 0) {
            return new Response('Invalid signature', 401);
        } else {
            echo openssl_error_string();
            return new Response('verify error', 401);
        }
        $subject = $payloadJson['sub'];
        /** @var User $user */
        $user = $this->getDoctrine()->getRepository('AppBundle:User')->findOneBySubject($subject);
        if ($user != null) {
            $providerKey = "main";
            $loginToken = new UsernamePasswordToken($user, null, $providerKey, $user->getRoles());
            $securityTokenStorage = $this->get('security.token_storage');
            $securityTokenStorage->setToken($loginToken);

            return $this->redirectToRoute('homepage');
        }

        $session = $request->getSession();
        $session->set('subject', $subject);
        $session->set('email', $payloadJson['email']);

        return $this->redirectToRoute('google_sign_up');
    }

    public function googleSignUpAction(Request $request, UserPasswordEncoderInterface $passwordEncoder)
    {
        $session = $request->getSession();
        $user = new User();
        $user->setSubject($session->get('subject'));
        $user->setEmail($session->get('email'));
        $user->setPlainPassword(random_bytes(10));

        $form = $this->createForm(GoogleSignUpType::class, $user);

        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            $password = $passwordEncoder->encodePassword($user, $user->getPlainPassword());
            $user->setPassword($password);

            $entityManager = $this->getDoctrine()->getManager();
            $entityManager->persist($user);
            $entityManager->flush();
            
            return $this->redirectToRoute('homepage');
        }

        return $this->render('security/sign_up.html.twig', array(
            'form' => $form->createView()
        ));
    }
}