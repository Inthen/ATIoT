# ATIoT
A tool for identifying potential attacks and generating corresponding attack trees for IoT systems from a system description

# Installation
ATIoT requires the installation of the GraphViz library in order for it to generate the attack trees.
1. Install graphviz
   The following command exemplifies the installation on Debian-based distributions:
```
sudo apt-get install graphviz
```
2. Install python dependencies:
```
graphviz
pydot
fpdf
```

# Use
To use ATIoT, simply run the python file and answer the questionnaire with the desired system description and properties. The tool will automatically select the relevant attacks and generate the PDF files for the relevant trees.

The file also includes functions for integration with Security Advising Modules (SAM), a framework that aggregates and connects the various modules developed under the scope of the [SECURIoTESIGN](https://lx.it.pt/securIoTesign/) project, such as ATIoT, while providing a graphical interface to interact with them. SAM's Web API or backend is availabe [here](https://github.com/SECURIoTESIGN/SAM-API/), while the frontend is available [here](https://github.com/SECURIoTESIGN/SAM/).

# Acknowledgment

This work was performed under the scope of Project SECURIoTESIGN, with funding from FCT/COMPETE/ FEDER (projects with reference numbers UIDB/50008/2020 and POCI-01-0145-FEDER-030657). This work is funded by Portuguese FCT/MCTES through national funds and, when applicable, co-funded by EU funds under the project UIDB/50008/2020, and FCT research and doctoral grants BIM/n\degree32/2018-B00582 and SFRH/BD/133838/2017, respectively, and also supported by operation Centro-01-0145-FEDER-000019 - C4 - Centro de Competências em Cloud Computing, co-financed by the European Regional Development Fund (ERDF) through the Programa Operacional Regional do Centro (Centro 2020), in the scope of the Sistema de Apoio à Investigação Científica e Tecnológica - Programas Integrados de IC\&DT.

