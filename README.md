Login Log Analyzer

This a tool that parses SSH authentication logs and flags suspicious login activity. It has three injected attacks (brute force, far apart IP addresses, and off-hours login)

I built this to practice log analysis and detection skills similar to the way an SOC analyst tool would.

HOW IT WORKS...

	generate_logs.py -- this is a synthetic SSH auth log generator with injected attacks.
	parser.py -- this is a regex based log parser with a structured DataFrame
	detector.py -- this contains functions (kind of like a playbook) for detecting the injected attacks
	report.py -- this is a CLI tool that produces a summary of the log data, CSV export, and a bar chart
	validate.py -- this checks the accuracy of the detector against the ground truth

RESULTS...
So far, the tool is able to detect all 3 of the injected attacks but it is also picking up some false positives which I am working to eliminate them by playing around with the threshold values.
