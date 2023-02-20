<?php 
class VerifyEmail { 

    protected $stream = false; 
    protected $port = 25; 
    protected $from = 'root@localhost'; 
    protected $max_connection_timeout = 30; 
    protected $stream_timeout = 5; 
    protected $stream_timeout_wait = 0; 
    protected $exceptions = false; 
    protected $error_count = 0; 
    public $Debug = false; 
    public $Debugoutput = 'echo'; 
    const CRLF = "\r\n"; 
    public $ErrorInfo = ''; 
    public function __construct($exceptions = false) { 
        $this->exceptions = (boolean) $exceptions; 
    } 
    public function setEmailFrom($email) { 
        if (!self::validate($email)) { 
            $this->set_error('Invalid address : ' . $email); 
            $this->edebug($this->ErrorInfo); 
            if ($this->exceptions) { 
                throw new verifyEmailException($this->ErrorInfo); 
            } 
        } 
        $this->from = $email; 
    } 
    public function setConnectionTimeout($seconds) { 
        if ($seconds > 0) { 
            $this->max_connection_timeout = (int) $seconds; 
        } 
    } 
    public function setStreamTimeout($seconds) { 
        if ($seconds > 0) { 
            $this->stream_timeout = (int) $seconds; 
        } 
    } 

    public function setStreamTimeoutWait($seconds) { 
        if ($seconds >= 0) { 
            $this->stream_timeout_wait = (int) $seconds; 
        } 
    } 
    public static function validate($email) { 
        return (boolean) filter_var($email, FILTER_VALIDATE_EMAIL); 
    } 
    public function getMXrecords($hostname) { 
        $mxhosts = array(); 
        $mxweights = array(); 
        if (getmxrr($hostname, $mxhosts, $mxweights) === FALSE) { 
            $this->set_error('MX records not found or an error occurred'); 
            $this->edebug($this->ErrorInfo); 
        } else { 
            array_multisort($mxweights, $mxhosts); 
        } 
        if (empty($mxhosts)) { 
            $mxhosts[] = $hostname; 
        } 
        return $mxhosts; 
    } 
    public static function parse_email($email, $only_domain = TRUE) { 
        sscanf($email, "%[^@]@%s", $user, $domain); 
        return ($only_domain) ? $domain : array($user, $domain); 
    } 
    protected function set_error($msg) { 
        $this->error_count++; 
        $this->ErrorInfo = $msg; 
    } 
    public function isError() { 
        return ($this->error_count > 0); 
    } 
    protected function edebug($str) { 
        if (!$this->Debug) { 
            return; 
        } 
        switch ($this->Debugoutput) { 
            case 'log': 
                error_log($str); 
                break; 
            case 'html': 
                echo htmlentities( 
                        preg_replace('/[\r\n]+/', '', $str), ENT_QUOTES, 'UTF-8' 
                ) 
                . "<br>\n"; 
                break; 
            case 'echo': 
            default: 
                $str = preg_replace('/(\r\n|\r|\n)/ms', "\n", $str); 
                echo gmdate('Y-m-d H:i:s') . "\t" . str_replace( 
                        "\n", "\n \t ", trim($str) 
                ) . "\n"; 
        } 
    } 
    public function check($email) { 
        $result = FALSE; 

        if (!self::validate($email)) { 
            $this->set_error("{$email} incorrect e-mail"); 
            $this->edebug($this->ErrorInfo); 
            if ($this->exceptions) { 
                throw new verifyEmailException($this->ErrorInfo); 
            } 
            return FALSE; 
        }
        $this->error_count = 0; // Reset errors 
        $this->stream = FALSE; 

        $mxs = $this->getMXrecords(self::parse_email($email)); 
        $timeout = ceil($this->max_connection_timeout / count($mxs)); 
        foreach ($mxs as $host) { 
            $this->stream = @stream_socket_client("tcp://" . $host . ":" . $this->port, $errno, $errstr, $timeout); 
            if ($this->stream === FALSE) { 
                if ($errno == 0) { 
                    $this->set_error("Problem initializing the socket"); 
                    $this->edebug($this->ErrorInfo); 
                    if ($this->exceptions) { 
                        throw new verifyEmailException($this->ErrorInfo); 
                    } 
                    return FALSE; 
                } else { 
                    $this->edebug($host . ":" . $errstr); 
                } 
            } else { 
                stream_set_timeout($this->stream, $this->stream_timeout); 
                stream_set_blocking($this->stream, 1); 

                if ($this->_streamCode($this->_streamResponse()) == '220') { 
                    $this->edebug("Connection success {$host}"); 
                    break; 
                } else { 
                    fclose($this->stream); 
                    $this->stream = FALSE; 
                } 
            } 
        } 

        if ($this->stream === FALSE) { 
            $this->set_error("All connection fails"); 
            $this->edebug($this->ErrorInfo); 
            if ($this->exceptions) { 
                throw new verifyEmailException($this->ErrorInfo); 
            } 
            return FALSE; 
        } 

		$this->_streamQuery("HELO " . self::parse_email($this->from));
		$this->_streamResponse();
		$this->_streamQuery("MAIL FROM: <{$this->from}>");                   
		$this->_streamResponse();
		$this->_streamQuery("RCPT TO: <{$email}>");
		$code = $this->_streamCode($this->_streamResponse());
		fclose($this->stream);
        $code = !empty($code2)?$code2:$code;
        switch ($code) { 
            case '250': 
            case '450':			
            case '451': 
            case '452': 
                return TRUE;
            case '550':
                return FALSE; 
            default : 
                return FALSE; 
        } 
    } 
    protected function _streamQuery($query) { 
        $this->edebug($query); 
        return stream_socket_sendto($this->stream, $query . self::CRLF); 
    } 
    protected function _streamResponse($timed = 0) { 
        $reply = stream_get_line($this->stream, 1); 
        $status = stream_get_meta_data($this->stream); 

        if (!empty($status['timed_out'])) { 
            $this->edebug("Timed out while waiting for data! (timeout {$this->stream_timeout} seconds)"); 
        } 

        if ($reply === FALSE && $status['timed_out'] && $timed < $this->stream_timeout_wait) { 
            return $this->_streamResponse($timed + $this->stream_timeout); 
        } 


        if ($reply !== FALSE && $status['unread_bytes'] > 0) { 
            $reply .= stream_get_line($this->stream, $status['unread_bytes'], self::CRLF); 
        } 
        $this->edebug($reply); 
        return $reply; 
    } 
    protected function _streamCode($str) { 
        preg_match('/^(?<code>[0-9]{3})(\s|-)(.*)$/ims', $str, $matches); 
        $code = isset($matches['code']) ? $matches['code'] : false; 
        return $code; 
    } 

} 
class verifyEmailException extends Exception { 
    public function errorMessage() {
        $errorMsg = $this->getMessage(); 
        return $errorMsg; 
    } 

} 
$mail = new VerifyEmail();
$mail->setStreamTimeoutWait(20);
$mail->setEmailFrom('wardoves@tourvest.co.za');
$array1 = [];
$array2 = [];

      
	$mailList = explode("\n", file_get_contents('checkme.txt'));

	if(!empty($mailList)){ foreach($mailList as $email){
		if($mail->check(trim($email))){
		
			echo 'Email '.$email.' is exist!'.'\n'; 
			array_push($array1, $email);
			$fp = fopen('validemail.txt', 'a');//opens file in append mode  
			fwrite($fp,"\n".trim($email));  
			fclose($fp); 
			
		}else{ 
 			
			echo 'Email '.$email.' is not valid and not exist!'.'\n'; 
			array_push($array2, $email);
			$fp = fopen('invalidemail.txt', 'a');//opens file in append mode  
			fwrite($fp,"\n".trim($email));  
			fclose($fp); 			
		} 
	} 
	}
$rand= rand();

file_put_contents( $rand.'-validemail.txt', $array1 );
file_put_contents( $rand.'-invalidemail.txt', $array2 );
?>
