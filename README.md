# mimic-tls

cat domains | ./mimic -stdin > results

cat results | python3 table.py
# Copy paste into table.tex
pdflatex table.tex

# evince table.pdf

