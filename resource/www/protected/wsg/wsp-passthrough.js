function m_create_slide_content() {
	var dsl_box = document.createElement("div");
	dsl_box.innerHTML = "<br><table align='center'><tr><td><img src='/protected/wsg/wait_wheel.gif'/></td><td width='10'></td>"
			+ "<td><input type='button' onClick='window.location.href=\""
			+ window.location.protocol
			+ "//"
			+ window.location.host
			+ "/"
			+ "\";' value='Cancel'/></td></tr></table>";
	return dsl_box;
}

function m_show_overlay() {
	m_slide_start(false, "WebSecureProxy Connection", m_create_slide_content(),
			null);
	setTimeout('m_poll_for_port()', 5000);
}

function m_poll_for_port() {
	var http = m_open_connection("/protected/wsg/ica-port");

	var sendData = "has port been received?";
	//http.setRequestHeader("Content-length", sendData.length);
	http.send(sendData);

	// alert("Received: " + http.responseText);

	if (http.responseText.indexOf("Port received!") != -1) {
		//alert("Port has been received...");
		m_slide_stop();
		return;
	}

	http.responseText = "";

	setTimeout('m_poll_for_port()', 5000);
}

function m_open_connection(strl_path) {
	if (window.XMLHttpRequest)
		http = new XMLHttpRequest(); // code for IE7+, Firefox, Chrome,
	// Opera, Safari
	else
		http = new ActiveXObject("Microsoft.XMLHTTP"); // code for IE6, IE5

	var strl_url = window.location.protocol + "//" + window.location.host
			+ strl_path;

	// alert("Connect to: " + strl_url);

	http.open("POST", strl_url, false);
	// http.setRequestHeader("Content-type",
	// "application/x-www-form-urlencoded");
	// http.setRequestHeader("Cookie", document.cookie);
	// http.setRequestHeader("Connection", "close");

	return http;
}

window.onbeforeunload = function() {
	// alert("We will now send a note to the webserver...");
	http = m_open_connection("/protected/wsg/ica-close");

	var sendData = "closed";
	//http.setRequestHeader("Content-length", sendData.length);
	http.send(sendData);
}
