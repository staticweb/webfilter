<?php

class Support extends Controller
{
	public function __construct()
	{
		parent::Controller();
		
		$this->load->model('Chrome');
		
		if (!empty($_REQUEST['DEBUG']) && $_REQUEST['DEBUG'] == '97') {
			$this->output->enable_profiler(TRUE);	
		}
		
		return true;
	}
	
	public function player() 
	{
		cacheHeaders(false);
		$data['mainnav_active'] = 100;

		$debug = $this->input->post('debug');
		
		echo $this->Chrome->getheader($data);

		$data['content_content'] = '<p>Nedenfor findes debug information som benyttes af YouSee Web-tv  support.</p>
		<pre>'.$debug.'</pre>';
		
		$data['content_header'] = 'Support';

		echo $this->parser->parse('content', $data, true);		

		echo $this->Chrome->getfooter();
	}	

	public function systemtest($ip = false) {
		cacheHeaders(false);

		$spocid = (!empty($_REQUEST['id'])) ? $_REQUEST['id'] : false; 
			

		if (!get_cookie('udid') && empty($_REQUEST['r'])) {
			if ($spocid) {
				redirect('/systemtest/'.(($ip) ? $ip : '').'/?r=1&id='.$spocid);
			} else {
				redirect('/systemtest/'.(($ip) ? $ip : '').'/?r=1');
			}
			exit;
		}
		
		if (!$ip || !$this->input->valid_ip($ip)) {
			$ip = $this->input->ip_address();
		}

	
		@delete_cookie('udid', '.yousee.tv', '/');
		@delete_cookie('acku', '.yousee.tv', '/');
		@delete_cookie('isD', '.yousee.tv', '/');
		
		$this->load->model('User');
		$this->load->model('Channels');
		$this->load->model('YSpro');
		$this->load->library('user_agent');

		$extraCustomerNo = '';
		if ($this->User->isLoggedIn()) {
			$hasCreditCard = $this->YSpro->getUserPaymentInfo($this->User->isLoggedIn());
			$ottEngagement = $this->YSpro->getOttEngagement($this->User->isLoggedIn(), true);
			$ottEngagement = json_decode($ottEngagement);
			$ottProducts = Array();
			foreach ($ottEngagement->Data as $product) {
				foreach ($product->Properties as $property) {
					if ($property->DataName == 'OttProduct') {
						$ottProducts[] = $property->Value;
					}	
				}
			}
			$ottEngagement = count($ottProducts);
			$userinfo = $this->YSpro->getUserInfo(false, $this->User->isLoggedIn(), 0, false, true);		
			$userinfoExp = explode("|", $userinfo);
			$extraCustomerNo = $userinfoExp[10]; 
		}
		
		$this->User->resetCache($ip, $this->User->getCustomerNoFromIp($ip), $this->User->isLoggedIn(), $extraCustomerNo);


		$data['mainnav_active'] = 100;

		$data['spocid'] = $spocid;

		echo $this->Chrome->getheader($data);

		$state = '';
		$message = '';

		if ($this->User->isYouSeeIp($ip)) {
			$state = 'ok';
			if ($this->User->isonfone) {
				$message = '<p>Du benytter et OnFone mobilabonnement. Du kan derfor se gratis Web-tv. Det eneste du skal g&oslash;re er at oprette et YouSee Login, eller benytte dit eksisterende YouSee Login.</p><p><strong>YouSee kundenr.:</strong> '.$this->User->getCustomerDataFromMsisdn(@$_SERVER[$this->config->item('msisdn_header')])->customerno.(($extraCustomerNo) ? '/'.$extraCustomerNo : '').'</p>';
			} else {
				$message = '<p>Du benytter YouSee bredb&aring;nd. Du kan derfor se gratis Web-tv. Det eneste du skal g&oslash;re er at oprette et YouSee Login, eller benytte dit eksisterende YouSee Login.</p><p><strong>YouSee kundenr./adresse-id:</strong> '.$this->User->getCustomerNoFromIp($ip).(($extraCustomerNo) ? '/'.$extraCustomerNo : '').'</p>';
			}
		}
		else if ($this->User->isUserInDenmark(true, $ip) == true) {
			$state = 'ok';
			$message = '<p>Du benytter en dansk internet forbindelse, og du kan derfor se Live-tv og film p&aring; YouSee Web-tv.</p>';
		} else {
			$state = 'warning';
			$message = '<p>Du benytter ikke en dansk internet forbindelse, og du kan derfor ikke se Live-tv og film p&aring; YouSee Web-tv. Du kan stadig benytte Tvguide.</p>';
		}

		$data['content_content'] = '
		<p><strong>Tidspunkt(al): </strong>'.date('r').'</p>
		
		<p class="'.$state.'">
			<strong>IP adresse: </strong>
			'.$ip.' ('.gethostbyaddr($ip).')</p>
			'.$message.'
		';
	
		$data['content_content'] .= '
		<p>
			<strong>Logget ind: </strong>
			'.(($this->User->isLoggedIn()) ? 'Du er logget ind' : 'Du er ikke logget ind').'.'.(($extraCustomerNo) ? '(Kundenr. : '.$extraCustomerNo.')' : '').'
		</p>
		';

		if ($this->User->isLoggedIn()) {
			$data['content_content'] .= '
			<p>
				<strong>Betalingskort tilknyttet: </strong> '.(($hasCreditCard) ? 'Ja' : 'Nej').'<br />
				<strong>Aktivt YouBio abonnement: </strong> '.(($ottEngagement) ? 'Ja' : 'Nej').'
			</p>	
			';
		}
		$versionno = floatval($this->agent->version());
		
		$state = 'warning';
		$message = '<p>YouSee Web-tv er ikke testet p&aring; din browser. Du er velkommen til at benytte YouSee Web-tv, men vi kan ikke garantere at det fungerer perfekt.<br />
		YouSee Web-tv anbefaler flg. browsere:<br />
		- Firefox 17.0 eller nyere<br />
		- Internet Explorer 8 eller nyere<br />
		- Safari 6 eller nyere
		';
		
		if ($this->agent->browser() == 'Firefox') {
			if ($versionno >= 3) {
				$state = 'ok';
				$message = '<p>YouSee Web-tv fungerer perfekt i din browser.</p>';
			} else {
				$state = 'warning';
				$message = '<p>For at opn&aring; den bedste oplevelse med YouSee.tv, anbefaler vi at du opdaterer din Firefox browser til nyeste version. Den nyeste version kan altid hentes p&aring; <a href="http://getfirefox.com" target="_blank">getfirefox.com</a>.'; 
			}
		}
		if ($this->agent->browser() == 'Internet Explorer') {
			if ($versionno >= 8) {
				$state = 'ok';
				$message = '<p>YouSee Web-tv fungerer perfekt i din browser.</p>';
			} else {
				$state = 'warning';
				$message = '<p>For at opn&aring; den bedste oplevelse med YouSee.tv, anbefaler vi at du opdaterer din Internet Explorer browser til nyeste version. Den nyeste version kan altid hentes p&aring; <a href="http://www.microsoft.com/windows/internet-explorer/default.aspx" target="_blank">microsoft.com</a>.'; 
			}
		}
		
		if ($this->agent->browser() == 'Safari') {
			if ($versionno >= 6) {
				$state = 'ok';
				$message = '<p>YouSee Web-tv fungerer perfekt i din browser.</p>';
			} else {
				$state = 'warning';
				$message = '<p>For at opn&aring; den bedste oplevelse med YouSee.tv, anbefaler vi at du opdaterer din Safari browser til nyeste version. Den nyeste version kan altid hentes p&aring; <a href="http://www.apple.com/safari/download/" target="_blank">apple.com</a>.'; 
			}
		}	

		if ($this->agent->browser() == 'Chrome') {
			if ($versionno >= 22) {
				$state = 'ok';
				$message = '<p>YouSee Web-tv fungerer perfekt i din browser.</p>';
			} else {
				$state = 'warning';
				$message = '<p>For at opn&aring; den bedste oplevelse med YouSee.tv, anbefaler vi at du opdaterer din Chrome browser til nyeste version. Den nyeste version kan altid hentes p&aring; <a href="http://www.google.com/chrome" target="_blank">google.com/chrome</a>.'; 
			}
		}							

		$data['content_content'] .= '
		<p class="'.$state.'" id="browser-check">
			<strong>Browser: </strong>
			'.$this->agent->browser().' '.$this->agent->version().'<br /><small>['.getenv('http_user_agent').']</small></p>
			'.$message.'
		';
		
		$data['content_content'] .= '
		<script type="text/javascript">
			var is32BitBrowser = true;
			if( window.navigator.cpuClass != null && window.navigator.cpuClass.toLowerCase() == "x64" )
		   		is32BitBrowser = false;
		   	if( window.navigator.platform.toLowerCase() == "win64" )
		      	is32BitBrowser = false;

			if (!is32BitBrowser) {
				$y(\'#browser-check, #browser-check + p\').remove();
				document.write(\'<p class="warning" style="border:2px solid red;padding:5px;margin:5px 0 5px 0"><strong>Du benytter en 64-bit browser. YouBio/Web-tv playeren virker desv&aelig;rre ikke i en 64-bit browser</strong></p>\');
			}	
		</script>
		';
		
		$data['content_content'] .= '
		<noscript>
			<p class="error">
				<strong>Javascript: </strong> Ikke sl&aring;et til.</p>
				<p>YouSee Web-tv fungerer ikke uden Javascript. Aktiver Javascript og vend tilbage til denne side for at verificere at det er aktiveret.</p>
			</p>
		</noscript>
		<script type="text/javascript">
			document.write(\'<p class="ok"><strong>Javascript: </strong> Sl&aring;et til.</p>\');
		</script>
		';

		$data['content_content'] .= '
		<script type="text/javascript">
			var playerVersion = swfobject.getFlashPlayerVersion(); // returns a JavaScript object
			var majorVersion = playerVersion.major;
			var minorVersion = playerVersion.minor;
			
			if (swfobject.hasFlashPlayerVersion("10.2")) {
				var hasflash = true;
				document.write(\'<p class="ok"><strong>Adobe Flash Player: </strong> Installeret</p>\');
				document.write(\'<p>Du har installeret Adobe Flash Player version \' + majorVersion + \'.\' + minorVersion + \', som er den anbefalede version til TV-arkiv p&aring; YouSee Web-tv</p>\');
			}
		</script>
		';
		
		$data['content_content'] .= '
		<script type="text/javascript">
			if (ytv.global.isPluginInstalled()) {
				document.write(\'<p class="ok"><strong>YouBio/Web-tv player: </strong> Installeret</p>\');
				document.write(\'<p>Du har installeret YouBio/Web-tv player programmet - og du kan derfor se film og Web-tv p&aring; YouBio og YouSee Web-tv</p>\');
				$y(\'body\').append(\'<div id="UniqIdHolder" style="visibility:hidden"/>\');
				if (/MSIE (\d+\.\d+);/.test(navigator.userAgent)) 
					$y(\'#UniqIdHolder\').append(\'<object id="UniqIdPlugin" classid="CLSID:059BFDA3-0AAB-419F-9F69-AF9BBE3A4668" width="1" height="1"></object>\');
				else
					$y(\'#UniqIdHolder\').append(\'<object id="UniqIdPlugin" type="application/x-viewright-m3u8" width="1" height="1"></object>\');
				try {
					document.write(\'<p>YouBio/Web-tv player version: <strong>\' + $y(\'#UniqIdPlugin\').get(0).GetVersion() + \'</strong></p>\');
					$y(\'#UniqIdPlugin\').get(0).Close();	
					$y(\'#UniqIdPlugin\').get(0).UnLoad();	
					$y(\'#UniqIdHolder\').remove();
				} catch(err) { }
			}
			else {
				document.write(\'<p class="warning"><strong>YouBio/Web-tv player: </strong> Ikke installeret</p>\');
				document.write(\'<p>Du har ikke installeret YouBio/Web-tv player. For at kunne se film og udvalgte Web-tv kanaler skal du benytte YouBio/Web-player. <br /><a href="/installation-af-plugin/" target="_blank">Klik her for installationsvejledning</a>.</p>\');

			}
		</script>
		';
		
		$data['content_content'] .= '
		<script type="text/javascript">
			if ($y.cookie(\'__utma\')) {
				document.write(\'<p class="ok"><strong>Cookies: </strong> Sl&aring;et til.</p><p>YouSee Web-tv benytter cookies n&aring;r du logger ind med dit YouSee login. Samtidig benyttes cookies ifbm. bes&oslash;gsstatistik.</p>\');
			} else {
				document.write(\'<p class="warning"><strong>Cookies: </strong> Sl&aring;et fra.</p><p>YouSee Web-tv benytter cookies n&aring;r du logger ind med dit YouSee login. Hvis cookies ikke er sl&aring;et til, kan du ikke se Live-tv eller film p&aring; YouSee Web-tv. Tvguide kan benyttes uden cookies.</p>\');
			}
		</script>		
		';
	

		$data['content_content'] .= '
		<script type="text/javascript">
			function youbiodnscheck() {
				clearTimeout(dnsproblem);
			}
		
			var dnsproblem = setTimeout(function() {
				$y(\'#youbio-dns-check\').hide().css(\'background\',\'red\').css(\'margin-bottom\',\'10px\').css(\'padding\',\'10px\').css(\'color\',\'#fff\').html(\'<p class="warning"><strong>DNS problem: </strong> kan ikke kontakte YouBio platform.</p><p style="padding:0">Dette kan skyldes at du benytter Google DNS, som desv&aelig;rre ikke understøtter YouBio.</p>\').fadeIn(\'slow\');
			
			}, 3000); 

			$y.ajax(\'http://ys-vod.ds.cdn.yousee.tv/iPhone/iPhone-src/vod/youbio-dns-check.js\', {
				dataType:\'jsonp\'
			});
		
		</script>	
		<div id="youbio-dns-check"></div>
		';

		$channels = $this->User->getAllowedChannels($ip, false, $this->User->isLoggedIn(), get_cookie('udid'));
		$channelinfo = $this->Channels->getChannelInfo($channels);

		$data['content_content'] .= '<p class="ok"><strong>Du har adgang til flg. kanaler:</strong><br />';
		foreach ($channelinfo as $channel) {
			$data['content_content'] .= $channel['nicename'].', ';
		}
		if (!count($channelinfo)) {
			$data['content_content'] .= 'ingen kanaler';
		}
		$data['content_content'] .= '</p>';

		$data['content_content'] .= '
		<p class="ok"><strong>Server information:</strong> '.$_SERVER['SERVER_NAME'].' ('.$_SERVER['SERVER_ADDR'].')</p>
		';

		$data['content_content'] .= '<div id="hastighedstest_result"></div>';
		$data['content_content'] .= '<div id="hastighedstest"></div>';
		$data['content_content'] .= '
		<script>
		swfobject.embedSWF("http://hastighedstest.yousee.dk/speedtest.swf?v=1.9.0", "hastighedstest", "426", "291", "7.0.0","/design/swf/expressInstall.swf", {}, {wmode:\'transparent\',menu:\'false\',allowscriptaccess:\'always\',quality:\'high\'},{});
		</script>';
	
		$data['content_content'] .= '
		<script>
		function download_completed(download_speed, upload_speed, server_id) {
			download_speed = download_speed / 1000;
			upload_speed = upload_speed / 1000;
			$y(\'#hastighedstest\').hide();
			$y(\'#hastighedstest_result\').html(\'<p><strong>Hastighedstest:</strong>: \' + \'Download hastighed: <strong>\' + download_speed + \'</strong> mb/sek \' + \'Upload hastighed: <strong>\' + upload_speed + \'</strong> mb/sek<br /><a href="#" onclick="$y(\\\'#hastighedstest\\\').show(); $y(\\\'#hastighedstest_result\\\').html(\\\'\\\');" class="green">Genstart test</a></p>\');
			if (document.location.hash == "#send" || "'.$spocid.'") {
				var data = \'\';
				$y(\'#left p\').each(function(i, item) {
					data += \'<p>\' + $y(item).html() + \'<\/p>\';
				});
				$y.post(\'/support/mailsystemtest/'.$spocid.'\', {data:data});
			}
		}
		if ((document.location.hash == "#send" || "'.$spocid.'") && !hasflash) {
				var data = \'\';
				$y(\'#left p\').each(function(i, item) {
					data += \'<p>\' + $y(item).html() + \'<\/p>\';
				});
				$y.post(\'/support/mailsystemtest/'.$spocid.'\', {data:data});
		}
		</script>	
		';	

		
		$data['content_header'] = 'System test';

		echo $this->parser->parse('content', $data, true);		

		echo $this->Chrome->getfooter();
	}

	public function systemcheck() {
		cacheHeaders(false);
		$this->load->Model('YSPro');

		header('Content-type: text/plain; charset=utf-8');
		header('X-OTT-Server-Ip: '.$_SERVER['SERVER_ADDR']);

		if ($this->config->item('platform') == 'dev') {
			$this->readdb = $this->load->database('thomasdev', true);
		} else {
			$this->readdb = $this->load->database('prod_read', true);
			if (!$this->readdb->initialize()) {
				$this->readdb = $this->load->database('prod', true);
			}
		}	
	
		$res = $this->db->count_all('movies');
		if (!$res) {
			header('Status: 500 Internal Server Error', true, 500);
			syslog(LOG_ERR, 'OTT SYSTEMCHECK: Cannot read from p-mysql01');
			echo 'Cannot read from p-mysql01';
			return;
		}
		$res = $this->readdb->count_all('movies');
		if (!$res) {
			header('Status: 500 Internal Server Error', true, 500);
			syslog(LOG_ERR, 'OTT SYSTEMCHECK: Cannot read from ottsqlslave');
			echo 'Cannot read from ottsqlslave';
			return;
		}

		$response = curl_file_get_contents('http://ptays.yousee.tv/ipscopes/?ip=8.8.8.8', false, 6);
		if (!$response) {
			header('Status: 500 Internal Server Error', true, 500);
			syslog(LOG_ERR, 'OTT SYSTEMCHECK: PTAYS does not respond');
			echo 'PTAYS does not respond';
			return;
		}

		$response = $this->YSPro->ping();
		if (!$response) {
			header('Status: 500 Internal Server Error', true, 500);
			syslog(LOG_ERR, 'OTT SYSTEMCHECK: YSPro does not respond');
			echo 'YSPro does not respond';
			return;
		}

		$response = json_decode($response);

		if ((int) $response->Status !== 0) {
			header('Status: 500 Internal Server Error', true, 500);
			syslog(LOG_ERR, 'OTT SYSTEMCHECK: YSPro says it is down');
			echo 'YSPro says it is down';
			return;
		}


		header('Status: 200 OK', true, 200);
		echo 'Everything is OK';
	}
	
	public function heartbeat() {
		cacheHeaders(false);

		$downtime = false;

		header('Content-type: text/plain; charset=utf-8');
		header('X-OTT-Server-Ip: '.$_SERVER['SERVER_ADDR']);

		if ($this->config->item('platform') == 'dev') {
			$this->readdb = $this->load->database('thomasdev', true);
		} else {
			$this->readdb = $this->load->database('prod_read', true);
			if (!$this->readdb->initialize()) {
				$this->readdb = $this->load->database('prod', true);
			}
		}	

		$res = $this->db->count_all('movies');
		if (!$res) {
			header('Status: 500 Internal Server Error', true, 500);
			syslog(LOG_ERR, 'OTT HEARTBEAT: Cannot read from ottsqlmaster');
			echo 'Cannot read from ottsqlmaster';
			return;
		}
		
		if ($downtime) {
			header('Status: 500 Internal Server Error', true, 500);
			echo 'Scheduled downtime';
			return;
		}

		header('Status: 200 OK', true, 200);
		echo 'Everything is OK';
	}

	public function message() {
		cacheHeaders(true, 300);
		$this->parser->parse('feeds/supportmessage', Array('message' => $this->Chrome->getsupportmessage()));
	}

	public function speedtest_settings() {
		$this->parser->parse('speedtest_settings', Array());
	}

	public function dktvipscopes() {
		cacheHeaders(false);
		$this->load->config('dktvscopes');
		header('Content-type: text/plain');
		$ipscopes = $this->config->item('dktvipscope');
		echo implode("\n", $ipscopes);
	
	}
	
	public function ipsinwhitelist() {
		cacheHeaders(false);
		header('Content-type: text/plain');
		$ipscopes = $this->config->item('foreignipswithaccess');
		asort($ipscopes);
		echo implode("\n", $ipscopes);
	
	}

	public function bptest($customerno) {
		cacheHeaders(false);

		$this->load->Model('basepointapi', 'bp');
		$this->load->Model('Movies');

		if (!$customerno) {
			die('missing customerno');
		}

		if ($this->config->item('platform') == 'dev') {
			$this->readdb = $this->load->database('thomasdev', true);
		} else {
			$this->readdb = $this->load->database('prod_read', true);
			if (!$this->readdb->initialize()) {
				$this->readdb = $this->load->database('prod', true);
			}
		}	
		
		$res = $this->readdb->select('content, content_desc')->group_by('content')->where('type', 'movie')->where('origin','yousee')->where('create_time >', '2012-12-01')->where('customerno', $customerno)->order_by('create_time', 'desc')->get('log_reststreams');

		echo '<table style="width:40%;float:left">';
		echo '<caption style="font-size:1.4em;font-weight:bold">In YouSee stream log</caption>';

		foreach ($res->result() as $row) {
			echo '<tr><td>'.$row->content.'</td><td>'.$row->content_desc.'</td></tr>';
		}

		echo '</table>';
		echo '<h1></h1>';
		$recommendations = $this->bp->user_product($customerno);

		echo '<table style="width:40%;float:left">';
		echo '<caption style="font-size:1.4em;font-weight:bold">http://bpm-recyou-prod.appspot.com/api/user_product/'.$customerno.' response</caption>';

		foreach ($recommendations as $recommendation) {
			$movie = $this->Movies->getMovie($recommendation->productid, 'id');
			echo '<tr><td>'.$movie['id'].'</td><td>'.$movie['title'].'</td></tr>';
		}

		echo '</table>';
	}

	public function mailsystemtest($spocid = false) {
		$data = $this->input->post('data');

		$subject = ((bool) $spocid) ? 'Systemtest [ ref:_00D20Hlzc._'.$spocid.':ref ]' : 'Systemtest sendt fra IP: '.$this->input->ip_address();
		
		$this->load->library('email');
		$this->load->model('User');
		
		$config['mailtype'] = 'html';
		$config['charset'] = 'iso-8859-1';
		$config['protocol'] = 'smtp';
		$config['smtp_host'] = $this->config->item('smtp_host');;
		$config['smtp_user'] = $this->config->item('smtp_user');;
		$config['smtp_pass'] = $this->config->item('smtp_pass');;
		$config['smtp_port'] = $this->config->item('smtp_port');;
		$config['newline'] = "\r\n";
		$config['crlf'] = "\r\n";
			
		$this->email->initialize($config);
	
		$mailbody = $this->parser->parse('mail/header', Array(), true).
		utf8_decode(strip_tags(str_replace("</p>", "\n\n", $data))).
		$this->parser->parse('mail/footer', Array(), true);

		$this->email->from('youseetv@youmail.dk', 'YouSee Web-tv');
		$this->email->reply_to('webtvsupport@yousee.dk', 'YouSee Web-tv');
		$this->email->to('webtvsupport@yousee.dk');
		$this->email->bcc('yousee.tv@gmail.com');
		$this->email->subject(utf8_decode($subject));
		$this->email->message(trim($mailbody));
		$this->email->send();

		echo $this->email->print_debugger();

		echo '1';
	}

}

?>
