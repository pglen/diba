AUTOMAKE_OPTIONS = foreign
#SUBDIRS = currency gui keygen tools server blockchain bluepoint common transport voting
SUBDIRS =  tools keygen #transport 

test:
	cd tools && make test && cd ..
	cd keygen && make test && cd ..

pub:
	git add .
	git commit -m "auto from mf"
	gt push

