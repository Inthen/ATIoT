import sys
import os
import pydot
import csv
from fpdf import FPDF

"""
// ---------------------------------------------------------------------------
//
//	Security Advising Modules (SAM) for Cloud IoT and Mobile Ecosystem
//
//  Copyright (C) 2023 Instituto de Telecomunicações (www.it.pt)
//  Copyright (C) 2023 Universidade da Beira Interior (www.ubi.pt)
//
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with this program.  If not, see <http://www.gnu.org/licenses/>.
// 
//  This work was performed under the scope of Project SECURIoTESIGN with funding 
//  from FCT/COMPETE/FEDER (Projects with reference numbers UID/EEA/50008/2013 and 
//  POCI-01-0145-FEDER-030657) 
// ---------------------------------------------------------------------------
"""

################################# TREE OUTPUTS #################################

trees_recommendations = ['Physical Tampering', 'Physical Damage', 'Theft', 'Side-Channel Attacks',
                         'Reverse Engineering', 'Sleep ', 'Deprivation', 'Jamming and Interference', 'Data Tampering',
                         'Data Theft', 'Data Replay', 'Data Poisoning', 'Data Injection', 'Traffic Analysis',
                         'Eavesdropping', 'Spoofing', 'Denial of Service', 'Man-in-the-Middle', 'Sniffing', 'Flooding',
                         'Sinkhole', 'Node Injection', 'Sybil', 'Social Engineering', 'Brute Force', 'Misconfiguration',
                         'Pharming', 'Denial of Service', 'Virus and Worms', 'Malware', 'SQL Injection',
                         'Cross-Site Scripting', 'Session Hijacking', 'Spoofing']


################################# FUNCTIONS #################################


"""
[Summary]: Common method to add recommendation.
[Arguments]: 
    - $recm_list$: A list containing the recommendations ID.
    - $recm$: A string that contains the recommendation abbreviation text.
    - $recommendations$: An array of JSON Objects that includes information about the available set of recommendations.
[Returns]: List of recommendations.
"""
def add_recommendation(recm_list, recm_abbv, recommendations):
    recm = trees_recommendations[recm_abbv]
    recm_id = get_recommendation_id(recommendations, recm)
    if recm_id not in recm_list:
        recm_list.append(recm_id)



def retrieve_vulnerabilities(SRE_answers, SBP_answers, TMS_answers, recommendations):
    ## Security Requirements Elicitation Answers
    answers = SRE_answers
    domain = get_answer_content(answers, 1)
    user = get_answer_content(answers, 2)
    if user.lower() == "yes":
        login = get_answer_content(answers, 3)
        sent_entity = get_answer_content(answers, 7)
    database = get_answer_content(answers, 10)
    regular_update = get_answer_content(answers, 11)
    third_party = get_answer_content(answers, 12)
    eavesdrop = get_answer_content(answers, 13)
    impersonate = get_answer_content(answers, 15)
    priv_info = get_answer_content(answers, 16)
    modify_hard = get_answer_content(answers, 17)

    ## Security Best Practices Guidelines Answers
    answers = SBP_answers
    db = get_answer_content(answers, 19)
    if db.lower() == "yes":
        type_data = get_answer_content(answers, 20)
    user_regis = get_answer_content(answers, 24)
    prog_lang = get_answer_content(answers, 26)
    input_form = get_answer_content(answers, 27)
    if input_form.lower() == "yes":
        upload_file = get_answer_content(answers, 28)
    logs = get_answer_content(answers, 29)

    ## Threat Modeling Solution Answers
    answers = TMS_answers
    crypto_algo = get_answer_content(answers, 96)
    priv_escal = get_answer_content(answers, 97)
    xml_store = get_answer_content(answers, 98)
    standard_err = get_answer_content(answers, 116)
    HDL = get_answer_content(answers, 104)
    OSAT_ent = get_answer_content(answers, 105)
    documented = get_answer_content(answers, 106)
    add_hard_unit = get_answer_content(answers, 107)
    isolation = get_answer_content(answers, 108)
    vuln_impl = get_answer_content(answers, 109)
    if vuln_impl.lower() == "yes":
        eval_behav = get_answer_content(answers, 110)
        code_review = get_answer_content(answers, 111)
        if code_review.lower() == "no":
            immutable_data = get_answer_content(answers, 112)
        spec_third_party = get_answer_content(answers, 113)
        protect_sens_code = get_answer_content(answers, 114)
        debug_funct = get_answer_content(answers, 115)

    ## Logic
    trees_to_draw = []
    if domain.lower() == "smart healthcare" or domain.lower() == "smart wearables" or domain.lower() == "smart toys" or domain.lower() == "smart transportation":
        add_recommendation(trees_to_draw, 'CWE-400', trees_recommendations)

    return (trees_to_draw)


"""
[Summary]: Common method to get answer content from module, based on the question text.
[Arguments]: 
    - $questions$: A JSON Object that includes the last session questions of a module.
    - $question_text$: An integer that contains the ID (in DB) of the question.
[Returns]: Answer content for specified question.
"""


def get_answer_content(questions, question_id):
    for question in questions:
        if question['id'] == question_id:
            answers = question['answer']
            if len(answers) == 1:
                answer = answers[0]['content']
            else:
                answer = []
                for ans in answers:
                    answer.append(ans['content'])
            return answer

    return []


"""
[Summary]: Common method to get recommendation id by comparing its content with the recommendation name.
[Arguments]: 
    - $recommendations$: A JSON Object that includes information about recommendations.
    - $recommendation_name$: A string that contains a recommendation name (content in JSON).
[Returns]: Recommendation ID.
"""


def get_recommendation_id(recommendations, recommendation_name):
    for rec in recommendations:
        if rec['content'] == recommendation_name:
            return rec['id']

    return None


"""
[Summary]: Common method to get answers from a dependency module.
[Arguments]: 
    - $number_id$: A integer that contains the dependency module ID.
[Returns]: Set of answers.
"""


def get_module_answers(number_id, session):
    modules = session['dependencies']
    for i in range(len(modules)):
        module = modules[i]['module']
        if module['id'] == number_id:
            return module

    return {}


"""
[Summary]: Default SAM's logic main method.
[Arguments]:
    - $session$: Python object that includes information about a session - Questions and user selected answers.
    - $recommendations$: An array of JSON Objects that includes information about the available set of recommendations.
[Returns]: MUST return an array of recommendation IDs.
"""


def run(session, recommendations):
    SRE_answers = get_module_answers(1, session)['last_session']['questions']
    SBP_answers = get_module_answers(2, session)['last_session']['questions']
    TMS_answers = session['questions']

    create_tree(phys_tampering_nodes, phys_tampering_description, "Physical Tampering")

    #final_recommendations = retrieve_vulnerabilities(SRE_answers, SBP_answers, TMS_answers, recommendations)
    #return final_recommendations


# Define the nodes and edges of the attack tree
phys_tampering_nodes = {
    'Physical Tampering': {'Access Device', 'Interfere with Device'},
    'Access Device': {'Physically Open Device', 'Connect to Exposed Port'},
    'Physically Open Device': {'Remove Component from Device', 'Probe Conductors', 'Access Hardware Component'},
    'Connect to Exposed Port': {'Read from Device','Write to Device'},
    'Remove Component from Device': {'Obtain firmware and sensitive data'},
    'Probe Conductors': {'Retrieve sensitive data, e.g., encryption keys, exposed data'},
    'Access Hardware Component': {'Identify components with potential vulnerabilities', 'Reverse Engineer Device'},
    'Interfere with Device': {'Modify Conditions Around Device', 'Move Device'}
}

phys_tampering_description = {
    'Access Device': "Physically access the device. This is possible in environments where the device is not fully "
                     "monitored, or left in the environment unattended.",
    'Interfere with Device': "Situations where the attacker does not physically interact with the device (i.e., "
                             "opening it or connect to it), but can physically move it or alter the environment "
                             "around it.",
    'Physically Open Device': "The attacker opens the shell of the device, and directly interacts with its internal "
                              "components.",
    'Connect to Exposed Port': "The attacker utilizes an active management or access port, e.g., USB or Ethernet. "
                               "Through it, the attacker may be able to gain access to e.g., configurations, "
                               "sensitive data, or inject malicious code.",
    'Remove Component from Device': "The attacker physically removes parts of the device, such as chips, memory or "
                                    "sensors. From these, the attacker may extract firmware, software, and sensitive "
                                    "data.",
    'Probe Conductors': "The attacker probes the physical conductors on the device (e.g., PCB traces), and attempts "
                        "to read data from the device while it is functioning. This may include, e.g., encryption "
                        "keys and other sensitive data.",
    'Access Hardware Component': "The attacker takes note of, e.g., serial numbers and component model or part "
                                 "numbers, to later search for potential vulnerabilities of that component, "
                                 "or reverse engineer it, being able to, e.g., copy proprietary proprietary designs.",
    'Modify Conditions around Device': "While not directly interfering with the device, the attacker influences its "
                                       "capabilities, such as causing changes in a sensor or disconnecting an actuator."
}

device_theft_nodes = {
    'Device Theft': {'Physical Removal of Device', 'Unauthorized Access to Device'},
    'Physical Removal of Device': {'Steal Device', 'Remove Device from Deployment'},
    'Unauthorized Access to Device': {'Bypass Device Security Measures', 'Exploit Default Credentials'}
}

device_theft_description = {
    'Physical Removal of Device': "The attacker physically steals the IoT device by removing it from its deployment "
                                  "location, potentially gaining access to sensitive data or using the device "
                                  "for malicious purposes.",
    'Unauthorized Access to Device': "The attacker gains unauthorized access to the IoT device, often by bypassing "
                                     "device security measures or exploiting default credentials, allowing them to "
                                     "control the device or extract sensitive information."
}

side_channel_nodes = {
    'Side-Channel Attacks': {'Power Analysis', 'Timing Analysis'},
    'Power Analysis': {'Differential Power Analysis', 'Simple Power Analysis'},
    'Timing Analysis': {'Cache Timing Attacks', 'Software-Based Timing Attacks'}
}

side_channel_description = {
    'Power Analysis': "The attacker exploits variations in power consumption to extract information, such as secret "
                      "keys or sensitive data, by analyzing power patterns during the operation of the IoT device.",
    'Timing Analysis': "The attacker leverages timing information, such as execution time or cache behavior, to deduce "
                       "sensitive data or cryptographic keys by observing the timing variations caused by the device's "
                       "operations."
}

reverse_engineering_nodes = {
    'Reverse Engineering Attack': {'Extract Firmware and Code', 'Analyze Hardware Design'},
    'Extract Firmware and Code': {'Dump Firmware', 'Observe Device Behavior'},
    'Analyze Hardware Design': {'Identify Circuitry and Components', 'Obtain Device Schematics'}
}

reverse_engineering_description = {
    'Extract Firmware and Code': "The attacker extracts the firmware or code from the IoT device, often by dumping "
                                 "the firmware or observing the device's behavior, to analyze its functionality, "
                                 "identify vulnerabilities, or extract sensitive information.",
    'Analyze Hardware Design': "The attacker analyzes the hardware design of the IoT device, including identifying "
                               "the circuitry, components, and obtaining device schematics, to understand its "
                               "functionality, identify vulnerabilities, or perform further attacks."
}

jamming_interference_nodes = {
    'Jamming and Interference Attack': {'Denial of Service', 'Signal Interference'},
    'Denial of Service': {'Continuous Signal Blocking', 'Selective Signal Blocking'},
    'Signal Interference': {'Noise Generation', 'Signal Manipulation'}
}

jamming_interference_description = {
    'Denial of Service': "The attacker disrupts the normal operation of IoT devices or networks by continuously "
                         "blocking signals, either in a general or selective manner, leading to a denial of service "
                         "for legitimate users.",
    'Signal Interference': "The attacker generates noise or manipulates the signals in the vicinity of IoT devices, "
                           "causing interference that can degrade communication quality, disrupt data transmission, "
                           "or compromise the reliability of the IoT system."
}

sleep_deprivation_nodes = {
    'Sleep Deprivation': {'Prevent Device Sleep', 'Prevent User Interaction'},
    'Prevent Device Sleep': {'Overload Device with Continuous Processing', 'Block Sleep Signals'},
    'Overload Device with Continuous Processing': {'Constantly Send or Receive Data'},
    'Block Sleep Signals': {'Interfere with Device Communication'},
    'Interfere with Device Communication': {'Jam Wireless Signals', 'Block Network Access'},
    'Jam Wireless Signals': {'Transmit Radio Frequency Interference'},
    'Block Network Access': {'Disable Wi-Fi or Cellular Connectivity'},
    'Prevent User Interaction': {'Disable User Interfaces', 'Create Distractions'},
    'Disable User Interfaces': {'Lock Screen or Input Controls'},
    'Create Distractions': {'Generate Continuous Notifications', 'Trigger Alarms'}
}

sleep_deprivation_description = {
    'Prevent Device Sleep': "The attacker prevents the IoT device from entering sleep or low-power modes, "
                            "which can disrupt its normal operation and potentially drain its battery.",
    'Overload Device with Continuous Processing': "The attacker continuously sends or receives data to overload "
                                                  "the device's processing capabilities, preventing it from entering "
                                                  "sleep mode.",
    'Block Sleep Signals': "The attacker interferes with the signals that trigger the device's sleep mode, "
                           "preventing it from entering a low-power state.",
    'Interfere with Device Communication': "The attacker disrupts the device's communication channels, which can "
                                           "prevent sleep signals from being received or block network access.",
    'Jam Wireless Signals': "The attacker transmits radio frequency interference to disrupt the wireless signals "
                            "used by the IoT device, causing communication disruptions and preventing sleep signals.",
    'Block Network Access': "The attacker disables Wi-Fi or cellular connectivity, preventing the device from "
                            "communicating with the network and receiving sleep signals.",
    'Prevent User Interaction': "The attacker targets the user interfaces of the IoT device to prevent user "
                                "interaction, potentially causing frustration or distraction.",
    'Disable User Interfaces': "The attacker locks the device's screen or input controls, preventing the user from "
                               "interacting with the device and potentially triggering its sleep mode.",
    'Create Distractions': "The attacker generates continuous notifications or triggers alarms to distract "
                           "the user and prevent them from interacting with the device effectively."
}

traffic_analysis_nodes = {
    'Traffic Analysis': {'Monitor Network Traffic', 'Analyze Encrypted Traffic'},
    'Monitor Network Traffic': {'Capture Network Packets', 'Analyze Packet Metadata'},
    'Capture Network Packets': {'Sniff Wireless Traffic', 'Tap into Wired Network'},
    'Analyze Packet Metadata': {'Identify Patterns', 'Extract Information'},
    'Analyze Encrypted Traffic': {'Perform Traffic Correlation', 'Cryptanalysis'},
    'Perform Traffic Correlation': {'Analyze Timing and Size Patterns', 'Identify Communication Endpoints'},
    'Cryptanalysis': {'Perform Cryptographic Analysis', 'Brute Force Decryption'}
}

traffic_analysis_description = {
    'Monitor Network Traffic': "The attacker intercepts and monitors the network traffic to gain information about "
                               "communication patterns, devices, or potential vulnerabilities.",
    'Capture Network Packets': "The attacker captures packets transmitted over the network, which can provide "
                               "insights into the content and structure of the communication.",
    'Analyze Packet Metadata': "The attacker examines the metadata of network packets, such as source/destination "
                               "addresses, packet size, timing information, or protocol headers, to identify patterns "
                               "and extract valuable information.",
    'Analyze Encrypted Traffic': "The attacker analyzes encrypted traffic to identify patterns, communication endpoints, "
                                 "or perform cryptographic analysis to break the encryption.",
    'Perform Traffic Correlation': "The attacker correlates different traffic flows based on timing and size patterns, "
                                   "allowing them to infer relationships and potentially gain more insights.",
    'Cryptanalysis': "The attacker attempts to break the encryption used in the traffic through cryptographic analysis "
                     "methods or by performing brute force decryption."
}

spoofing_nodes = {
    'Spoofing': {'ARP Spoofing', 'DNS Spoofing', 'IP Spoofing'},
    'ARP Spoofing': {'Poison ARP Cache', 'Redirect Network Traffic'},
    'DNS Spoofing': {'Manipulate DNS Responses', 'DNS Cache Poisoning'},
    'IP Spoofing': {'Forge IP Packets', 'Impersonate Another Device'}
}

spoofing_description = {
    'ARP Spoofing': "The attacker sends forged Address Resolution Protocol (ARP) messages to associate their MAC "
                    "address with a different IP address in the network, leading to network traffic redirection "
                    "or interception.",
    'DNS Spoofing': "The attacker manipulates DNS responses to redirect or deceive network devices into resolving "
                    "domain names to malicious IP addresses controlled by the attacker.",
    'IP Spoofing': "The attacker forges the source IP address in IP packets to impersonate another device or hide "
                   "their identity, potentially enabling unauthorized access or bypassing security mechanisms."
}

dos_nodes = {
    'Denial of Service': {'Flooding Attack', 'Resource Exhaustion'},
    'Flooding Attack': {'UDP Flood', 'TCP SYN Flood'},
    'Resource Exhaustion': {'CPU Exhaustion', 'Memory Exhaustion'}
}

dos_description = {
    'Flooding Attack': "The attacker overwhelms the target device or network by sending a large volume of traffic, "
                       "causing it to become unresponsive or unavailable.",
    'Resource Exhaustion': "The attacker depletes critical resources of the target device, such as CPU or memory, "
                           "to degrade its performance or cause it to crash."
}

mitm_nodes = {
    'Man-in-the-Middle': {'Intercept Communication', 'Impersonate Communication Parties'},
    'Intercept Communication': {'Sniff Network Traffic', 'Decrypt Encrypted Traffic'},
    'Impersonate Communication Parties': {'Spoof Device Identities', 'Forge Digital Signatures'}
}

mitm_description = {
    'Intercept Communication': "The attacker intercepts network traffic between communicating devices, allowing them "
                               "to eavesdrop on the communication or perform other malicious activities.",
    'Impersonate Communication Parties': "The attacker impersonates legitimate devices or entities involved in the "
                                         "communication to gain unauthorized access or deceive other parties.",
    'Sniff Network Traffic': "The attacker captures and analyzes network traffic to gain access to sensitive data or "
                             "extract valuable information from the communication.",
    'Decrypt Encrypted Traffic': "The attacker decrypts encrypted traffic by intercepting and manipulating the "
                                 "communication flow or exploiting vulnerabilities in encryption protocols.",
    'Spoof Device Identities': "The attacker spoofs the identities of legitimate devices involved in the communication "
                               "to gain unauthorized access, manipulate data, or deceive other parties.",
    'Forge Digital Signatures': "The attacker forges digital signatures to impersonate legitimate entities or tamper "
                                "with the integrity and authenticity of the communication."
}

flooding_nodes = {
    'Flooding Attack': {'Network Flooding', 'Protocol Flooding'},
    'Network Flooding': {'ICMP Flood', 'UDP Flood', 'TCP Flood'},
    'Protocol Flooding': {'DNS Flood', 'HTTP Flood'}
}

flooding_description = {
    'Network Flooding': "The attacker overwhelms the network or specific network protocols with a high volume of "
                        "malicious traffic, causing congestion and potential disruption of normal operations.",
    'Protocol Flooding': "The attacker floods a specific protocol, such as DNS or HTTP, with a large number of "
                         "requests, consuming server resources and potentially causing denial of service."
}

sinkhole_nodes = {
    'Sinkhole Attack': {'Compromise Routing Protocol', 'Attract Traffic to Malicious Node'},
    'Compromise Routing Protocol': {'Manipulate Routing Information', 'Spoof Routing Advertisements'},
    'Attract Traffic to Malicious Node': {'Advertise False Services', 'Redirect Traffic'}
}

sinkhole_description = {
    'Compromise Routing Protocol': "The attacker compromises the routing protocol in the network to manipulate or spoof "
                                   "routing information, diverting traffic towards the attacker-controlled malicious "
                                   "node(s).",
    'Attract Traffic to Malicious Node': "The attacker advertises false services or redirects legitimate traffic to "
                                         "attract it towards their malicious node(s), allowing them to intercept or "
                                         "manipulate the traffic."
}

node_injection_nodes = {
    'Node Injection': {'Gain Unauthorized Access', 'Inject Malicious Code'},
    'Gain Unauthorized Access': {'Exploit Weak Authentication', 'Bypass Access Controls'},
    'Inject Malicious Code': {'Execute Remote Code', 'Plant Malware'}
}

node_injection_description = {
    'Gain Unauthorized Access': "The attacker exploits weak authentication mechanisms or bypasses access controls "
                                "to gain unauthorized access to an IoT node, providing them with control over the "
                                "device or network.",
    'Inject Malicious Code': "The attacker injects malicious code into the targeted IoT node, enabling them to execute "
                             "remote commands or plant malware to compromise the node's security or integrity."
}

sybil_nodes = {
    'Sybil Attack': {'Create Multiple Fake Identities', 'Impersonate Legitimate Nodes'},
    'Create Multiple Fake Identities': {'Generate Fake MAC Addresses', 'Create Pseudo-Identities'},
    'Impersonate Legitimate Nodes': {'Forge Digital Signatures', 'Masquerade as Legitimate Nodes'}
}

sybil_description = {
    'Create Multiple Fake Identities': "The attacker creates multiple fake identities or pseudo-identities, often "
                                       "associated with unique MAC addresses, to deceive the network and gain control "
                                       "or disrupt its operation.",
    'Impersonate Legitimate Nodes': "The attacker impersonates legitimate nodes in the network, either by forging "
                                    "digital signatures or masquerading as those nodes, to gain unauthorized access "
                                    "or manipulate the communication."
}

eavesdropping_nodes = {
    'Eavesdropping Attack': {'Monitor Network Traffic', 'Capture and Analyze Data'},
    'Monitor Network Traffic': {'Sniff Wireless Traffic', 'Tap into Wired Network'},
    'Capture and Analyze Data': {'Extract Sensitive Information', 'Perform Traffic Analysis'}
}

eavesdropping_description = {
    'Monitor Network Traffic': "The attacker monitors the network traffic, either by sniffing wireless traffic or "
                               "tapping into the wired network, to intercept and capture data exchanged between IoT "
                               "devices.",
    'Capture and Analyze Data': "The attacker captures and analyzes the intercepted data to extract sensitive "
                                "information or perform traffic analysis to gain insights into the communication "
                                "patterns and potential vulnerabilities."
}

sniffing_nodes = {
    'Sniffing Attack': {'Monitor Network Traffic', 'Capture and Analyze Data'},
    'Monitor Network Traffic': {'Sniff Wireless Traffic', 'Tap into Wired Network'},
    'Capture and Analyze Data': {'Extract Sensitive Information', 'Perform Traffic Analysis'}
}

sniffing_description = {
    'Monitor Network Traffic': "The attacker monitors the network traffic, either by sniffing wireless traffic or "
                               "tapping into the wired network, to intercept and capture data exchanged between IoT "
                               "devices.",
    'Capture and Analyze Data': "The attacker captures and analyzes the intercepted data to extract sensitive "
                                "information or perform traffic analysis to gain insights into the communication "
                                "patterns and potential vulnerabilities."
}

data_tampering_nodes = {
    'Data Tampering': {'Modify Data in Transit', 'Modify Stored Data'},
    'Modify Data in Transit': {'Intercept and Modify Data Packets', 'Alter Sensor Readings'},
    'Modify Stored Data': {'Manipulate Data at Rest', 'Tamper with Data Integrity'}
}

data_tampering_description = {
    'Modify Data in Transit': "The attacker intercepts data packets in transit between IoT devices or nodes and "
                              "modifies their content or alters the readings from sensors, leading to manipulated "
                              "or erroneous data.",
    'Modify Stored Data': "The attacker manipulates or tampers with data stored in IoT devices or backend systems, "
                          "either by directly modifying data at rest or compromising the integrity of stored data."
}

data_theft_nodes = {
    'Data Theft': {'Unauthorized Access to Data', 'Steal Data during Transit'},
    'Unauthorized Access to Data': {'Bypass Access Controls', 'Exploit Weak Authentication'},
    'Steal Data during Transit': {'Intercept Data Packets', 'Capture and Extract Data'}
}

data_theft_description = {
    'Unauthorized Access to Data': "The attacker gains unauthorized access to IoT devices or backend systems to "
                                   "illegitimately retrieve or steal sensitive data, often by bypassing access "
                                   "controls or exploiting weak authentication mechanisms.",
    'Steal Data during Transit': "The attacker intercepts data packets during transit between IoT devices or nodes, "
                                 "capturing and extracting the data for unauthorized purposes or data theft."
}
data_replay_nodes = {
    'Data Replay Attack': {'Capture and Store Data', 'Replay Captured Data'},
    'Capture and Store Data': {'Record Data in Transit', 'Log Sensor Readings'},
    'Replay Captured Data': {'Resend Captured Data', 'Replay Sensor Readings'}
}

data_replay_description = {
    'Capture and Store Data': "The attacker captures and stores data packets or sensor readings during transit or "
                              "from IoT devices, creating a repository of data for subsequent replay attacks.",
    'Replay Captured Data': "The attacker resends or replays previously captured data packets or sensor readings, "
                            "potentially to deceive systems, gain unauthorized access, or manipulate the behavior of "
                            "IoT devices."
}

data_poisoning_nodes = {
    'Data Poisoning Attack': {'Inject Malicious Data', 'Manipulate Training Data'},
    'Inject Malicious Data': {'Introduce False Sensor Readings', 'Alter Data Labels'},
    'Manipulate Training Data': {'Modify Training Data Distribution', 'Inject Adversarial Examples'}
}

data_poisoning_description = {
    'Inject Malicious Data': "The attacker injects malicious or false data into the IoT system, such as introducing "
                             "false sensor readings or altering data labels, to manipulate the behavior or decision-"
                             "making processes of the system.",
    'Manipulate Training Data': "The attacker manipulates the training data used in machine learning models or "
                                "algorithms by modifying their distribution or injecting adversarial examples, "
                                "resulting in compromised or biased models."
}

data_injection_nodes = {
    'Data Injection Attack': {'Intercept and Modify Data', 'Forge Data'},
    'Intercept and Modify Data': {'Tamper with Data in Transit', 'Alter Sensor Readings'},
    'Forge Data': {'Create and Inject False Data', 'Spoof Data Sources'}
}

data_injection_description = {
    'Intercept and Modify Data': "The attacker intercepts data packets or sensor readings in transit between IoT "
                                 "devices or nodes and modifies the content, leading to the injection of malicious "
                                 "data or manipulation of the system's behavior.",
    'Forge Data': "The attacker creates and injects false or fabricated data into the IoT system, often by spoofing "
                  "data sources or generating misleading information to deceive the system or influence its operation."
}

social_engineering_nodes = {
    'Social Engineering Attack': {'Phishing', 'Pretexting'},
    'Phishing': {'Email Phishing', 'Spear Phishing'},
    'Pretexting': {'Impersonation', 'Fake Support Calls'}
}

social_engineering_description = {
    'Phishing': "The attacker sends fraudulent emails or messages that appear to be from a legitimate source, "
                "tricking users into revealing sensitive information or performing actions that compromise their "
                "IoT system security.",
    'Pretexting': "The attacker creates a false pretense, such as impersonating a trusted entity or initiating fake "
                  "support calls, to manipulate users into disclosing sensitive information or granting unauthorized "
                  "access to their IoT system."
}

brute_force_nodes = {
    'Brute Force Attack': {'Credential Guessing', 'Password Cracking'}
}

brute_force_description = {
    'Credential Guessing': "The attacker systematically attempts different usernames and passwords in order to gain "
                           "unauthorized access to the IoT system by exploiting weak or commonly used credentials.",
    'Password Cracking': "The attacker employs automated tools or techniques to crack passwords, such as using "
                         "brute force methods or leveraging leaked password databases, to gain unauthorized access "
                         "to the IoT system."
}

misconfiguration_nodes = {
    'Misconfiguration Attack': {'Default Configurations', 'Insecure Configurations'},
    'Default Configurations': {'Default Passwords', 'Default Settings'},
    'Insecure Configurations': {'Weak Security Settings', 'Improper Access Controls'}
}

misconfiguration_description = {
    'Default Configurations': "The attacker targets IoT devices or systems that have default passwords or settings "
                              "that have not been changed, exploiting these known defaults to gain unauthorized "
                              "access or control over the IoT system.",
    'Insecure Configurations': "The attacker exploits weak security settings or improper access controls in the IoT "
                               "system, such as weak encryption, open ports, or misconfigured permissions, to gain "
                               "unauthorized access or compromise the security of the system."
}

pharming_nodes = {
    'Pharming Attack': {'DNS Spoofing', 'Router Compromise'},
    'DNS Spoofing': {'DNS Cache Poisoning', 'Phishing DNS'},
    'Router Compromise': {'Compromised Router Firmware', 'Router DNS Hijacking'}
}

pharming_description = {
    'DNS Spoofing': "The attacker manipulates DNS responses to redirect users to malicious websites or servers, "
                    "misleading them into providing sensitive information or compromising their IoT system.",
    'Router Compromise': "The attacker compromises the firmware or DNS settings of a router in the IoT system to "
                         "redirect users to malicious websites or servers, enabling them to carry out phishing or "
                         "other attacks."
}

dos_app_nodes = {
    'Denial of Service Attack': {'Network-Based DoS', 'Application-Based DoS'},
    'Network-Based DoS': {'TCP/IP Flooding', 'ICMP Flooding'},
    'Application-Based DoS': {'HTTP Flood', 'DNS Amplification'}
}
 
dos_app_description = {
    'Network-Based DoS': "The attacker floods the network infrastructure or IoT devices with a high volume of TCP/IP "
                         "or ICMP packets, overwhelming their processing capabilities and causing a denial of service.",
    'Application-Based DoS': "The attacker targets specific applications or services in the IoT system, flooding them "
                             "with a large number of HTTP requests or exploiting DNS amplification techniques to "
                             "exhaust resources and disrupt their normal operation, resulting in a denial of service."
}

virus_worms_nodes = {
    'Virus and Worms Attack': {'Propagation', 'Execution and Payload'},
    'Propagation': {'Email Attachments', 'USB Drives'},
    'Execution and Payload': {'Data Corruption', 'Unauthorized Access'}
}

virus_worms_description = {
    'Propagation': "The attacker spreads viruses or worms within the IoT system by leveraging email attachments or USB "
                   "drives, tricking users or devices into executing the malicious code and further spreading it.",
    'Execution and Payload': "The attacker executes the virus or worm on infected IoT devices, leading to data "
                             "corruption, unauthorized access, or the execution of a specific payload, compromising "
                             "the integrity and security of the IoT system."
}
malware_nodes = {
    'Malware Attack': {'Delivery', 'Execution and Persistence'},
    'Delivery': {'Phishing Emails', 'Drive-by Downloads'},
    'Execution and Persistence': {'Spyware', 'Ransomware'}
}

malware_description = {
    'Delivery': "The attacker delivers malware to the IoT system through various methods, such as phishing emails or "
                "drive-by downloads, tricking users or exploiting vulnerabilities in their devices to initiate the "
                "infection.",
    'Execution and Persistence': "The attacker executes the malware on the infected IoT devices, enabling activities "
                                 "like information gathering (spyware) or encrypting data and demanding ransom "
                                 "(ransomware), persistently compromising the security and functionality of the IoT "
                                 "system."
}

sql_injection_nodes = {
    'SQL Injection Attack': {'Injection Techniques', 'Unauthorized Data Access'},
    'Injection Techniques': {'Union-Based Injection', 'Boolean-Based Injection'},
    'Unauthorized Data Access': {'Extract Data', 'Modify Database'}
}

sql_injection_description = {
    'Injection Techniques': "The attacker exploits vulnerabilities in IoT application input fields by injecting SQL "
                            "statements, such as union-based or boolean-based injections, to manipulate the "
                            "underlying database queries.",
    'Unauthorized Data Access': "The attacker gains unauthorized access to the IoT application's database by "
                                "extracting sensitive data or modifying the database contents, potentially "
                                "compromising the integrity and confidentiality of the IoT system."
}

drawn_nodes = []

"""
[Summary]: Method that draws an edge of the tree.
[Arguments]: 
    - $parent_name$: A string that contains the parent node name.
    - $child_name$:  A string that contains the child node name.
[Returns]: Void.
"""


def draw(graph, parent_name, child_name):
    edge = pydot.Edge(parent_name, child_name, color="darkslateblue")
    graph.add_edge(edge)


"""
[Summary]: Recursive Method that iterates through a dictionary to create the corresponding tree.
[Arguments]: 
    - $nodes_dict$: The dictionary containing the tree information.
    - $parent$:  The parent node from where the drawing is starting. Default None for the first node of the tree
[Returns]: Void.
"""


def visitDict(graph, nodes_dict, parent=None):

    if parent is None:
        graph.add_node(pydot.Node(list(nodes_dict.keys())[0], shape="oval", color="red"))
        n = list(nodes_dict.keys())[0]
        c = list(nodes_dict.get(n))
        for a in list(c):
            if a is not None:
                if a not in drawn_nodes:
                    new_node = pydot.Node(a, shape="oval", color="red")
                    graph.add_node(new_node)
                drawn_nodes.append(a)
                draw(graph, n, a)
                visitDict(graph, nodes_dict, a)
    else:
        n = nodes_dict.get(parent)
        if n is not None:
            for a in list(n):
                if a not in drawn_nodes:
                    new_node = pydot.Node(a, shape="oval", color="red")
                    graph.add_node(new_node)
                draw(graph, parent, a)
                visitDict(graph, nodes_dict, a)


"""
PDF Class Definition for file header and footer
"""


class PDF(FPDF):
    def header(self):
        # SAM Logo
        self.image('sam.png', 10, 8, 20)
        # Line break
        self.ln(5)

    # Page footer
    def footer(self):
        # Position at 1.5 cm from bottom
        self.set_y(-15)
        # Project Logo
        #self.image('project.png', 10, None, 25)
        # Arial italic 8
        self.set_font('Arial', 'I', 8)
        # Page number
        self.cell(0, 10, str(self.page_no()), 0, 0, 'C')


"""
[Summary]: Method to create the final PDF of the tree and the descriptions of each node.
[Arguments]: 
    - $output_file_name$: The name of the pdf file to be written.
    - $tree_graph$:  The Dot format graph of the tree.
    - $pdf_title$: The title of the PDF file.
[Returns]: Void.
"""


def createTreePDF(output_file_name, tree_graph, tree_description, session_id, pdf_title="default"):
    tree_graph.write_png('tree.png')
    pdffile = PDF(orientation="L")
    pdffile.set_top_margin(20)
    pdffile.add_page()
    pdffile.set_title(pdf_title)
    pdffile.set_font('Arial', 'B', 16)
    pdffile.cell(0, 0, "Data Tampering", align='C')
    pdffile.ln(20)
    pdffile.image('tree.png', w=280)
    pdffile.ln(10)
    pdffile.set_font('Arial', "", 12)
    for node in tree_description:
        pdffile.multi_cell(0, 5, node + ": " + tree_description.get(node))
        pdffile.ln(5)

    pdffile.output(output_file_name, "F")
    # pdf.output('temp/session'+str(session_id)+'/session'+str(session_id)+'.pdf', 'F')


"""
[Summary]: Method to create the tree and the descriptions of each node.
[Arguments]: 
    - $tree_nodes$: Dictionary containing nodes and edges of the tree.
    - $tree_nodes_description$:  Dictionary containing descriptions for the nodes.
    - $graph_name$: The title of the attack tree.
[Returns]: Void.
"""


def create_tree(tree_nodes, tree_nodes_description, graph_name, session_id):

    graph = pydot.Dot(graph_type='digraph', dpi=300)
    visitDict(graph, tree_nodes)
    graph.set_name(graph_name)
    createTreePDF(graph_name+'.pdf', graph, tree_nodes_description, session_id, graph_name)

printed_nodes = []

def visit_text_tree(visited_nodes, nodes_dict, depth, parent=None):

    if parent is None:
        visited_nodes.append(list(nodes_dict.keys())[0])
        n = list(nodes_dict.keys())[0]
        c = list(nodes_dict.get(n))
        print("| " + n)
        for a in list(c):
            if a is not None:
                if a not in printed_nodes:
                    print("|     | " + a)
                printed_nodes.append(a)
                visit_text_tree(visited_nodes, nodes_dict, 2, a)
    else:
        n = nodes_dict.get(parent)
        if n is not None:
            for a in list(n):
                if a not in printed_nodes:
                    for i in range(depth):
                        print("|     ", end="")
                    print("| " + a)
                visit_text_tree(visited_nodes, nodes_dict, depth + 1, a)


def initialize_attacks_dict():
    dict_ = {
        "Physical Tampering": 0,
        "Theft": 0,
        "Side-Channel Attacks": 0,
        "Reverse Engineering": 0,
        "Sleep Deprivation": 0,
        "Jamming & Interference": 0,
        "Data Tampering": 0,
        "Data Theft": 0,
        "Data Replay": 0,
        "Data Poisoning": 0,
        "Data Injection": 0,
        "Traffic Analysis": 0,
        "Sniffing": 0,
        "Eavesdropping": 0,
        "Flooding": 0,
        "Spoofing": 0,
        "Sinkhole": 0,
        "Denial of Service": 0,
        "Node Injection": 0,
        "Man-in-the-Middle": 0,
        "Sybil": 0,
        "Social Engineering": 0,
        "Misconfiguration": 0,
        "Brute Force": 0,
        "Pharming": 0,
        "Virus and Worms": 0,
        "Malware": 0,
        "SQL Injection": 0,
    }

    return dict_


def initialize_answers_dict():

    q_dict = {
        "Q1": ["1 - Healthcare", "2 - Wearables", "3 - Agriculture or Environmental Monitoring", "4 - Smart Grids", "5 - Transportation and Logistics", "6 - Smart Home, Office or Building", "7 - Smart Manufacturing", "8 - Smart Cities"],
        "Q2": ["1- Yes", "2 - No"],
        "Q2.1": ["1 - Yes", "2 - No"],
        "Q3": ["1 - Yes", "2 - No"],
        "Q4": ["1 - Yes", "2 - No"],
        "Q4.1": ["1 - Normal information", "2 - Sensitive information", "3 - Critical information"],
        "Q4.2": ["1 - Yes", "2 - No"],
        "Q5": ["1- Device-Gateway-Cloud scheme", "2 - Device-Application scheme", "3 - Device-Cloud scheme"],
        "Q6": ["1 - Yes", "2 - No"],
        "Q7": ["1 - Yes", "2 - No"],
        "Q8": ["1 - Yes", "2 - No"],
        "Q9": ["1 - Locally", "2 - In the cloud", "3 - In an application", "4 - In a hybrid manner"],
        "Q10": ["1 - Yes", "2 - No"],
        "Q10.1": ["1 - Manually", "2 - Over the air"],
        "Q11": ["1 - Yes", "2 - No"],
        "Q12": ["1 - Yes", "2 - No"],
        "Q13": ["1 - Yes", "2 - No"],
        "Q14": ["1 - Yes", "2 - No"],
        "Q15": ["1 - Microcontroller", "2 - Single-Board Computer", "3 - Custom hardware"],
        "Q16": ["1 - Real Time", "2 - Embedded Linux", "3 - Linux", "4 - Custom"],
        "Q17": ["1 - Wi-fi", "2 - Cellular", "3 - Wired", "4 - Bluetooth", "5 - Zigbee", "6 - Z-wave", "7 - NFC", "8 - RFID"],
        "Q18": ["1 - Short", "2 - Medium", "3 - Long"],
        "Q19": ["1 - Continuous", "2 - Intermittent", "3 - Occasional"],
        "Q20": ["1 - CoAP", "2 - MQTT", "3 - HTTPS", "4 - Proprietary", "5 - Other protocol type"],
    }

    return q_dict


def initialize_Questions_dict():
    text_dict = {
        "Q1": ["Choose the domain type for your IoT system."],
        "Q2": ["Will the system have a user?"],
        "Q2.1": ["Will the system have user login?"],
        "Q3": ["Will the system hold any user information?"],
        "Q4": ["Will the system store any kind of information?"],
        "Q4.1": ["What will the level of stored information be?"],
        "Q4.2": ["Will this information be sent to an external entity?"],
        "Q5": ["How will the system transmit data?"],
        "Q6": ["Will the system be connected to the internet?"],
        "Q7": ["Will it send its data to a cloud?"],
        "Q8": ["Will it store data in a database?"],
        "Q9": ["Where will data be stored?"],
        "Q10": ["Will the system receive regular updates?"],
        "Q10.1": ["How will the system receive software updates?"],
        "Q11": ["Will the system work with third-party software?"],
        "Q12": ["Could the messages sent between the system components be captured and resent?"],
        "Q13": ["Can someone try to impersonate a user to gain access to private information?"],
        "Q14": ["Can someone gain physical access to the system/components and/or perform any modifications?"],
        "Q15": ["What type of processing hardware will the devices use?"],
        "Q16": ["What type of operating system will the devices run?"],
        "Q17": ["What type of network connectivity will the devices use?"],
        "Q18": ["What is the expected lifespan of the system?"],
        "Q19": ["What is the expected usage pattern of the system?"],
        "Q20": ["What are the expected communication protocols and/or data formats used by the system?"]
    }

    return text_dict


def questionnaire():

    print("Welcome to ATIoT. You will be asked a series of questions on your IoT system. Please answer accordingly.\n")
    print("At the end, a set of attacks will be outputted, together with the corresponding attack trees.\n")

    questions = initialize_Questions_dict()
    answers = initialize_answers_dict()

    while True:
        print("\n")
        print("#  Question 1 \n")
        print(questions["Q1"][0])
        print(*answers["Q1"])
        q1 = input("Please insert your answer: ")
        if (q1 == '1' or q1 == '2' or q1 == '3' or q1 == '4' or q1 == '5' or q1 == '6' or q1 == '7' or q1 == '8'):
            break
        else:
            print("Insert a valid answer \n")

    while True:
        print("\n")
        print("#  Question 2 \n")
        print(questions["Q2"][0])
        print(*answers["Q2"])
        q2 = input("Please insert your answer: ")
        if (q2 == '1' or q2 == '2'):
            break
        else:
            print("Insert a valid answer \n")

    if q2 == '1':
        while True:
            print("\n")
            print("#  Question 2.1 \n")
            print(questions["Q2.1"][0])
            print(*answers["Q2.1"])
            q2_1= input("Please insert your answer: ")
            if (q2_1 == '1' or q2_1 == '2'):
                break
            else:
                print("Insert a valid answer \n")
    else:
        q2_1 = -1

    while True:
        print("\n")
        print("#  Question 3 \n")
        print(questions["Q3"][0])
        print(*answers["Q3"])
        q3 = input("Please insert your answer: ")
        if (q3 == '1' or q3 == '2'):
            break
        else:
            print("Insert a valid answer \n")

    while True:
        print("\n")
        print("#  Question 4 \n")
        print(questions["Q4"][0])
        print(*answers["Q4"])
        q4 = input("Please insert your answer: ")
        if (q4 == '1' or q4 == '2'):
            break
        else:
            print("Insert a valid answer \n")

    if q4 == '1':
        while True:
            print("\n")
            print("#  Question 4.1 \n")
            print(questions["Q4.1"][0])
            print(*answers["Q4.1"])
            q4_1 = input("Please insert your answer: ")
            if (q4_1 == '1' or q4_1 == '2' or q4_1 == '3'):
                break
            else:
                print("Insert a valid answer \n")
    else:
        q4_1 = -1

    if q4 == '1':
        while True:
            print("\n")
            print("#  Question 4.2 \n")
            print(questions["Q4.2"][0])
            print(*answers["Q4.2"])
            q4_2 = input("Please insert your answer: ")
            if (q4_2 == '1' or q4_2 == '2'):
                break
            else:
                print("Insert a valid answer \n")
    else:
        q4_2 = -1

    while True:
        print("\n")
        print("#  Question 5 \n")
        print(questions["Q5"][0])
        print(*answers["Q5"])
        q5 = input("Please insert your answer: ")
        if (q5 == '1' or q5 == '2' or q5 =='3'):
            break
        else:
            print("Insert a valid answer \n")

    while True:
        print("\n")
        print("#  Question 6 \n")
        print(questions["Q6"][0])
        print(*answers["Q6"])
        q6 = input("Please insert your answer: ")
        if (q6 == '1' or q6 == '2'):
            break
        else:
            print("Insert a valid answer \n")

    while True:
        print("\n")
        print("#  Question 7 \n")
        print(questions["Q7"][0])
        print(*answers["Q7"])
        q7 = input("Please insert your answer: ")
        if (q7 == '1' or q7 == '2'):
            break
        else:
            print("Insert a valid answer \n")

    while True:
        print("\n")
        print("#  Question 8 \n")
        print(questions["Q8"][0])
        print(*answers["Q8"])
        q8 = input("Please insert your answer: ")
        if (q8 == '1' or q8 == '2'):
            break
        else:
            print("Insert a valid answer \n")

    while True:
        print("\n")
        print("#  Question 9 \n")
        print(questions["Q9"][0])
        print(*answers["Q9"])
        q9 = input("Please insert your answer: ")
        if (q9 == '1' or q9 == '2' or q9 == '3' or q9 == '4'):
            break
        else:
            print("Insert a valid answer \n")

    while True:
        print("\n")
        print("#  Question 10 \n")
        print(questions["Q10"][0])
        print(*answers["Q10"])
        q10 = input("Please insert your answer: ")
        if (q10 == '1' or q10 == '2'):
            break
        else:
            print("Insert a valid answer \n")

    if q10 == '1':
        while True:
            print("\n")
            print("#  Question 10.1 \n")
            print(questions["Q10.1"][0])
            print(*answers["Q10.1"])
            q10_1 = input("Please insert your answer: ")
            if (q10_1 == '1' or q10_1 == '2'):
                break
            else:
                print("Insert a valid answer \n")
    else:
        q10_1 = -1

    while True:
        print("\n")
        print("#  Question 11 \n")
        print(questions["Q11"][0])
        print(*answers["Q11"])
        q11 = input("Please insert your answer: ")
        if (q11 == '1' or q11 == '2'):
            break
        else:
            print("Insert a valid answer \n")

    while True:
        print("\n")
        print("#  Question 12 \n")
        print(questions["Q12"][0])
        print(*answers["Q12"])
        q12 = input("Please insert your answer: ")
        if (q12 == '1' or q12 == '2'):
            break
        else:
            print("Insert a valid answer \n")

    while True:
        print("\n")
        print("#  Question 13 \n")
        print(questions["Q13"][0])
        print(*answers["Q13"])
        q13 = input("Please insert your answer: ")
        if (q13 == '1' or q13 == '2'):
            break
        else:
            print("Insert a valid answer \n")

    while True:
        print("\n")
        print("#  Question 14 \n")
        print(questions["Q14"][0])
        print(*answers["Q14"])
        q14 = input("Please insert your answer: ")
        if (q14 == '1' or q14 == '2'):
            break
        else:
            print("Insert a valid answer \n")

    while True:
        print("\n")
        print("#  Question 15 \n")
        print(questions["Q15"][0])
        print(*answers["Q15"])
        q15 = input("Please insert your answer: ")
        if (q15 == '1' or q15 == '2' or q15 == '3'):
            break
        else:
            print("Insert a valid answer \n")

    while True:
        print("\n")
        print("#  Question 16 \n")
        print(questions["Q16"][0])
        print(*answers["Q16"])
        q16 = input("Please insert your answer: ")
        if (q16 == '1' or q16 == '2' or q16 == '3' or q16 == '4'):
            break
        else:
            print("Insert a valid answer \n")

    while True:
        print("\n")
        print("#  Question 17 \n")
        print(questions["Q17"][0])
        print(*answers["Q17"])
        q17 = input("Please insert your answer: ")
        if (q17 == '1' or q17 == '2' or q17 == '3' or q17 == '4' or q17 == '5' or q17 == '6' or q17 == '7' or q17 == '8'):
            break
        else:
            print("Insert a valid answer \n")

    while True:
        print("\n")
        print("#  Question 18 \n")
        print(questions["Q18"][0])
        print(*answers["Q18"])
        q18 = input("Please insert your answer: ")
        if (q18 == '1' or q18 == '2' or q18 == '3'):
            break
        else:
            print("Insert a valid answer \n")

    while True:
        print("\n")
        print("#  Question 19 \n")
        print(questions["Q19"][0])
        print(*answers["Q19"])
        q19 = input("Please insert your answer: ")
        if (q19 == '1' or q19 == '2' or q19 == '3'):
            break
        else:
            print("Insert a valid answer \n")

    while True:
        print("\n")
        print("#  Question 20 \n")
        print(questions["Q20"][0])
        print(*answers["Q20"])
        q20 = input("Please insert your answer: ")
        if (q20 == '1' or q20 == '2' or q20 == '3' or q20 == '4' or q20 == '5'):
            break
        else:
            print("Insert a valid answer \n")

    print("Questionnaire Finished! Your selected attacks are as follows:\n")

    file = open('answers.csv', 'w')

    file.write(str(q1) + ', ' + str(q2) + ', ' + str(q2_1) + ', ' +
                           str(q3) + ', ' + str(q4) + ', ' + str(q4_1) + ', ' + str(q4_2) + ', ' +
                           str(q5) + ', ' + str(q6) + ', ' + str(q7) + ', ' +
                           str(q8) + ', ' + str(q9) + ', ' +
                           str(q10) + ', ' + str(q10_1) + ', ' + str(q11) + ', ' +
                           str(q12) + ', ' + str(q13) + ', ' + str(q14) + ', ' +
                           str(q15) + ', ' + str(q16) + ', ' + str(q17) + ', ' +
                           str(q18) + ', ' + str(q19) + ', ' + str(q20) + ', ' + '\n')


def insert_attacks(dict_attacks, list_attacks, list_values):
    if len(list_attacks) != len(list_values):
        raise ValueError("Size of the attacks is different from the expected value.")

    for i, sec_prop in enumerate(list_attacks):
        dict_attacks[sec_prop] = list_values[i]


questionnaire()

f1 = open('answers.csv', 'r')

texts_dict = initialize_Questions_dict()
answers_dict = initialize_answers_dict()

count = 0
while True:
    line = f1.readline()
    lis = line.split(",")
    del lis[-1]
    answer = [eval(i) for i in lis]
    if not line:
        break

    attacks_dict = initialize_attacks_dict()

    if answer[0] == 1:

        attacks = ["Sleep Deprivation", "Jamming & Interference", "Data Tampering", "Data Theft", "Data Replay",
                   "Data Poisoning", "Data Injection"]

        values = [1, 1, 1, 1, 1, 1, 1]
        insert_attacks(attacks_dict, attacks, values)

    elif answer[0] == 2:
        attacks = ["Sleep Deprivation", "Jamming & Interference", "Social Engineering"]
        values = [1, 1, 1]
        insert_attacks(attacks_dict, attacks, values)

    elif answer[0] == 3:
        attacks = ["Physical Tampering", "Theft", "Reverse Engineering", "Sleep Deprivation"]
        values = [1, 1, 1, 1]
        insert_attacks(attacks_dict, attacks, values)

    elif answer[0] == 4:
        attacks = ["Physical Tampering", "Reverse Engineering", "Jamming & Interference", "Data Tampering",
                   "Data Theft", "Data Replay", "Data Poisoning", "Data Injection", "Traffic Analysis",
                   "Denial of Service", "Flooding", "Sinkhole", "Node", "Sybil"]
        values = [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
        insert_attacks(attacks_dict, attacks, values)

    elif answer[0] == 5:
        attacks = ["Physical Tampering", "Theft", "Data Theft", "Jamming & Interference"]
        values = [1, 1, 1, 1]
        insert_attacks(attacks_dict, attacks, values)

    elif answer[0] == 6:
        attacks = ["Physical Tampering", "Theft", "Data Poisoning", "Jamming & Interference", "Node Injection"]
        values = [1, 1, 1, 1, 1]
        insert_attacks(attacks_dict, attacks, values)

    elif answer[0] == 7:
        attacks = ["Phsyical Tampering", "Theft", "Data Injection", "Data Poisoning", "Jamming & Interference"]
        values = [1, 1, 1, 1, 1]
        insert_attacks(attacks_dict, attacks, values)

    elif answer[0] == 8:
        attacks = ["Physical Tampering", "Theft", "Sleep Deprivation", "Jamming & Interference",
                   "Denial of Service", "Flooding", "Sinkhole", "Sybil", "Pharming"]
        values = [1, 1, 1, 1, 1, 1, 1, 1, 1]
        insert_attacks(attacks_dict, attacks, values)

    if answer[1] == 2:
        attacks = ["Brute Force", "Social Engineering"]
        values = [0, 0]
        insert_attacks(attacks_dict, attacks, values)

    if answer[2] == 1:
        attacks = ["Brute Force", "Social Engineering", "SQL Injection"]
        values = [1, 1, 1]
        insert_attacks(attacks_dict, attacks, values)

    elif answer[2] == 2:
        attacks = ["Brute Force", "Social Engineering"]
        values = [0, 0]
        insert_attacks(attacks_dict, attacks, values)

    if answer[3] == 1:
        attacks = ["Data Theft"]
        values = [1]
        insert_attacks(attacks_dict, attacks, values)

    if answer[4] == 1:
        attacks = ["Data Theft"]
        values = [1]
        insert_attacks(attacks_dict, attacks, values)

    elif answer[4] == 2:
        attacks = ["Data Theft"]
        values = [0]
        insert_attacks(attacks_dict, attacks, values)

    if answer[5] == 1:
        attacks = ["Data Theft"]
        values = [1]
        insert_attacks(attacks_dict, attacks, values)

    elif answer[5] == 2:
        attacks = ["Data Tampering", "Data Theft", "Social Engineering", "Data Poisoning", "Data Injection"]
        values = [1, 1, 1, 1, 1]
        insert_attacks(attacks_dict, attacks, values)

    elif answer[5] == 3:
        attacks = ["Data Tampering", "Data Theft", "Social Engineering", "Data Poisoning", "Data Injection"]
        values = [1, 1, 1, 1, 1]
        insert_attacks(attacks_dict, attacks, values)

    if answer[6] == 1:
        attacks = ["Data Theft", "Data Poisoning", "Data Injection"]
        values = [1, 1, 1]
        insert_attacks(attacks_dict, attacks, values)

    if answer[7] == 1:
        attacks = ["Eavesdropping", "Jamming & Interference"]
        values = [1, 1]
        insert_attacks(attacks_dict, attacks, values)

    elif answer[7] == 2:
        attacks = ["Traffic Analysis", "Spoofing", "Denial of Service", "Man-in-the-Middle"]
        values = [1, 1, 1, 1]
        insert_attacks(attacks_dict, attacks, values)

    elif answer[7] == 3:
        attacks = ["Denial of Service", "Man-in-the-Middle", "Sniffing", "Sinkhole", "Node Injection"]
        values = [1, 1, 1, 1, 1]
        insert_attacks(attacks_dict, attacks, values)

    if answer[8] == 1:
        attacks = ["Traffic Analysis", "Denial of Service", "Malware"]
        values = [1, 1, 1]
        insert_attacks(attacks_dict, attacks, values)

    if answer[9] == 1:
        attacks = ["Data Theft"]
        values = [1]
        insert_attacks(attacks_dict, attacks, values)

    if answer[10] == 1:
        attacks = ["Data Theft"]
        values = [1]
        insert_attacks(attacks_dict, attacks, values)

    if answer[11] == 1:
        attacks = ["Physical Tampering", "Theft", "Data Theft"]
        values = [1, 1, 1]
        insert_attacks(attacks_dict, attacks, values)

    elif answer[11] == 2:
        attacks = ["Physical Tampering", "Theft", "Data Theft"]
        values = [1, 1, 1]
        insert_attacks(attacks_dict, attacks, values)

    elif answer[11] == 3:
        attacks = ["Data Theft", "Man-in-the-Middle"]
        values = [1, 1]
        insert_attacks(attacks_dict, attacks, values)

    if answer[13] == 1:
        attacks = ["Misconfiguration", "Man-in-the-Middle", "Pharming", "Spoofing"]
        values = [1, 1, 1, 1]
        insert_attacks(attacks_dict, attacks, values)

    if answer[13] == 2:
        attacks = ["Social Engineering", "Pharming", "Virus and Worms"]
        values = [1, 1, 1]
        insert_attacks(attacks_dict, attacks, values)

    if answer[14] == 1:
        attacks = ["Social Engineering", "Misconfiguration"]
        values = [1, 1]
        insert_attacks(attacks_dict, attacks, values)

    if answer[15] == 1:
        attacks = ["Data Replay"]
        values = [1]
        insert_attacks(attacks_dict, attacks, values)

    if answer[16] == 1:
        attacks = ["Data Tampering", "Data Theft", "Data Poisoning", "Data Injection"]
        values = [1, 1, 1, 1]
        insert_attacks(attacks_dict, attacks, values)

    if answer[17] == 1:
        attacks = ["Physical Tampering", "Side-Channel Attacks", "Reverse Engineering", "Jamming & Interference"]
        values = [1, 1, 1, 1]
        insert_attacks(attacks_dict, attacks, values)

    if answer[17] == 2:
        attacks = ["Physical Tampering", "Theft", "Side-Channel Attacks", "Reverse Engineering"]
        values = [0, 0, 0, 0]
        insert_attacks(attacks_dict, attacks, values)

    if answer[18] == 1:
        attacks = ["Physical Tampering", "Side-Channel Attacks"]
        values = [1, 1]
        insert_attacks(attacks_dict, attacks, values)

    elif answer[18] == 2:
        attacks = ["Physical Tampering", "Side-Channel Attacks"]
        values = [1, 1]
        insert_attacks(attacks_dict, attacks, values)

    elif answer[18] == 3:
        attacks = ["Reverse Engineering", "Side-Channel Attacks"]
        values = [1, 1]
        insert_attacks(attacks_dict, attacks, values)

    if answer[19] == 1:
        attacks = ["Sinkhole", "Denial of Service"]
        values = [1, 1]
        insert_attacks(attacks_dict, attacks, values)

    elif answer[19] == 2:
        attacks = ["Sleep Deprivation", "Flooding", "Malware"]
        values = [1, 1, 1]
        insert_attacks(attacks_dict, attacks, values)

    elif answer[19] == 3:
        attacks = ["Sleep Deprivation", "Flooding", "Malware"]
        values = [1, 1, 1]
        insert_attacks(attacks_dict, attacks, values)

    elif answer[19] == 4:
        attacks = ["Reverse Engineering"]
        values = [1]
        insert_attacks(attacks_dict, attacks, values)

    if answer[20] == 1:
        attacks = ["Eavesdropping", "Sniffing", "Denial of Service"]
        values = [1, 1, 1]
        insert_attacks(attacks_dict, attacks, values)

    elif answer[20] == 2:
        attacks = ["Eavesdropping", "Sniffing", "Denial of Service"]
        values = [1, 1, 1]
        insert_attacks(attacks_dict, attacks, values)

    elif answer[20] == 3:
        attacks = ["Eavesdropping", "Sniffing", "Denial of Service"]
        values = [1, 1, 1]
        insert_attacks(attacks_dict, attacks, values)

    elif answer[20] == 4:
        attacks = ["Jamming & Interference", "Flooding", "Node Injection", "Sinkhole", "Sybil"]
        values = [1, 1, 1, 1, 1]
        insert_attacks(attacks_dict, attacks, values)

    elif answer[20] == 5:
        attacks = ["Jamming & Interference", "Flooding", "Node Injection", "Sinkhole", "Sybil"]
        values = [1, 1, 1, 1, 1]
        insert_attacks(attacks_dict, attacks, values)

    elif answer[20] == 6:
        attacks = ["Jamming & Interference", "Side-Channel Attacks", "Physical tampering"]
        values = [1, 1, 1]
        insert_attacks(attacks_dict, attacks, values)

    elif answer[20] == 7:
        attacks = ["Physical tampering", "Theft", "Social Engineering"]
        values = [1, 1, 1]
        insert_attacks(attacks_dict, attacks, values)

    if answer[21] == 2:
        attacks = ["Reverse Engineering", "Misconfiguration"]
        values = [1, 1]
        insert_attacks(attacks_dict, attacks, values)

    elif answer[21] == 3:
        attacks = ["Reverse Engineering", "Misconfiguration", "Brute Force"]
        values = [1, 1, 1]
        insert_attacks(attacks_dict, attacks, values)

    if answer[22] == 1:
        attacks = ["Denial of Service", "Eavesdropping", "Traffic Analysis"]
        values = [1, 1, 1]
        insert_attacks(attacks_dict, attacks, values)

    elif answer[22] == 2:
        attacks = ["Sleep Deprivation", "Denial of Service"]
        values = [1, 1]
        insert_attacks(attacks_dict, attacks, values)

    elif answer[22] == 3:
        attacks = ["Sleep Deprivation", "Spoofing", "Node Injection"]
        values = [1, 1, 1]
        insert_attacks(attacks_dict, attacks, values)

    if answer[23] == 1:
        attacks = ["Eavesdropping", "Traffic Analysis", "Man-in-the-Middle"]
        values = [1, 1, 1]
        insert_attacks(attacks_dict, attacks, values)

    elif answer[23] == 2:
        attacks = ["Sniffing", "Denial of Service"]
        values = [1, 1]
        insert_attacks(attacks_dict, attacks, values)

    elif answer[23] == 3:
        attacks = ["Eavesdropping", "Traffic Analysis", "Man-in-the-Middle"]
        values = [1, 1, 1]
        insert_attacks(attacks_dict, attacks, values)

    elif answer[23] == 4:
        attacks = ["Side-Channel Attacks", "Reverse Engineering", "Traffic Analysis", "Misconfiguration"]
        values = [1, 1, 1, 1]
        insert_attacks(attacks_dict, attacks, values)

    reqList = [0 for i in range(0, 28)]

    if attacks_dict["Physical Tampering"] == 1:
        create_tree(phys_tampering_nodes, phys_tampering_description, "Physical_Tampering", 0)
        reqList[0] = 1

    if attacks_dict["Theft"] == 1:
        create_tree(device_theft_nodes, device_theft_description, "Theft", 0)
        reqList[1] = 1
    if attacks_dict["Side-Channel Attacks"] == 1:
        create_tree(side_channel_nodes, side_channel_description, "Side_Channel_Attacks", 0)
        reqList[2] = 1
    if attacks_dict["Reverse Engineering"] == 1:
        create_tree(reverse_engineering_nodes, reverse_engineering_description, "Reverse_Engineering", 0)
        reqList[3] = 1
    if attacks_dict["Sleep Deprivation"] == 1:
        create_tree(sleep_deprivation_nodes, sleep_deprivation_description, "Sleep_Deprivation", 0)
        reqList[4] = 1
    if attacks_dict["Jamming & Interference"] == 1:
        create_tree(jamming_interference_nodes, jamming_interference_description, "Jamming_and_Interference", 0)
        reqList[5] = 1
    if attacks_dict["Data Tampering"] == 1:
        create_tree(data_tampering_nodes, data_tampering_description, "Data_Tampering", 0)
        reqList[6] = 1
    if attacks_dict["Data Theft"] == 1:
        create_tree(data_theft_nodes, data_theft_description, "Data_Theft", 0)
        reqList[7] = 1
    if attacks_dict["Data Replay"] == 1:
        create_tree(data_replay_nodes, data_replay_description, "Data_Replay", 0)
        reqList[8] = 1
    if attacks_dict["Data Poisoning"] == 1:
        create_tree(data_poisoning_nodes, data_poisoning_description, "Data_Poisoning", 0)
        reqList[9] = 1
    if attacks_dict["Data Injection"] == 1:
        create_tree(data_injection_nodes, data_injection_description, "Data_Injection", 0)
        reqList[10] = 1
    if attacks_dict["Traffic Analysis"] == 1:
        create_tree(traffic_analysis_nodes, traffic_analysis_description, "Traffic_Analysis", 0)
        reqList[11] = 1
    if attacks_dict["Sniffing"] == 1:
        create_tree(sniffing_nodes, sniffing_description, "Sniffing", 0)
        reqList[12] = 1
    if attacks_dict["Eavesdropping"] == 1:
        create_tree(eavesdropping_nodes, eavesdropping_description, "Eavesdropping", 0)
        reqList[13] = 1
    if attacks_dict["Flooding"] == 1:
        create_tree(flooding_nodes, flooding_description, "Flooding", 0)
        reqList[14] = 1
    if attacks_dict["Spoofing"] == 1:
        create_tree(spoofing_nodes, spoofing_description, "Spoofing", 0)
        reqList[15] = 1
    if attacks_dict["Sinkhole"] == 1:
        create_tree(sinkhole_nodes, sinkhole_description, "Sinkhole", 0)
        reqList[16] = 1
    if attacks_dict["Denial of Service"] == 1:
        create_tree(dos_nodes, dos_description, "Denial_of_Service", 0)
        reqList[17] = 1
    if attacks_dict["Node Injection"] == 1:
        create_tree(node_injection_nodes, node_injection_description, "Node_Injection", 0)
        reqList[18] = 1
    if attacks_dict["Man-in-the-Middle"] == 1:
        create_tree(mitm_nodes, mitm_description, "Man_in_the_Middle", 0)
        reqList[19] = 1
    if attacks_dict["Sybil"] == 1:
        create_tree(sybil_nodes, sybil_description, "Sybil", 0)
        reqList[20] = 1
    if attacks_dict["Social Engineering"] == 1:
        create_tree(social_engineering_nodes, social_engineering_description, "Social_Engineering", 0)
        reqList[21] = 1
    if attacks_dict["Misconfiguration"] == 1:
        create_tree(misconfiguration_nodes, misconfiguration_description, "Misconfiguration", 0)
        reqList[22] = 1
    if attacks_dict["Brute Force"] == 1:
        create_tree(brute_force_nodes, brute_force_description, "Brute_Force", 0)
        reqList[23] = 1
    if attacks_dict["Pharming"] == 1:
        create_tree(pharming_nodes, pharming_description, "Pharming", 0)
        reqList[24] = 1
    if attacks_dict["Virus and Worms"] == 1:
        create_tree(virus_worms_nodes, virus_worms_description, "Virus_and_Worms", 0)
        reqList[25] = 1
    if attacks_dict["Malware"] == 1:
        create_tree(malware_nodes, malware_description, "Malware", 0)
        reqList[26] = 1
    if attacks_dict["SQL Injection"] == 1:
        create_tree(sql_injection_nodes, sql_injection_description, "SQL_Injection", 0)
        reqList[27] = 1

    value = {i for i in attacks_dict if attacks_dict[i] == 1}
    print(*value, sep='\n')

# with open('tree.txt', 'w') as sys.stdout:
#    visit_text_tree([], phys_tampering_nodes, 0)
