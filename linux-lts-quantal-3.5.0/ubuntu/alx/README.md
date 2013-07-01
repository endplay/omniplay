# alx standalone development tree

The puropose of this development tree is to enable us to do development
on alx for both BSD and Linux with a single unified repository. This enables
us to synchronize fixes for both BSD and Linux. The idea is to help end
typical proprietary driver development for good:

http://www.youtube.com/watch?v=9P-r3H0bY8c

# Linux support

Linux support targets the alx driver to be built in synch with
linux-next.git as the base development tree. Backport kernel support
is provided by utilizing the compat-drivers framework.

To build for linux you will need a few trees. We have scripts to let
you get all that you need:

<pre>
cd ~
git clone git://github.com/mcgrof/compat.git
cd compat
./bin/get-compat-trees

cd ~
mkdir unified/
git clone git://github.com/mcgrof/alx.git

cd alx
./make linux
</pre>

# Contributions

Contributions to compat follow the same mechanisms as used in the Linux kernel,
this means you should provide as Singed-off-by tag as documented on the
Developer's Certificate of Origin 1.1.

# Submitting patches

compat and compat-drivers contributions follow the contribution model
implemented by the Linux kernel. Patches or pull requests for compat and
compat-drivers must have be signed-offed. If you don't sign off on them they
will not accepted. This means adding a line that says "Signed-off-by: Name
email" at the end of each commit, indicating that you wrote the code and have
the right to pass it on as an open source patch. For exact definition of what
the Signed-off-by tag is you can read the definition of the "Developer's
Certificate of Origin 1.1", which you can read here:

http://gerrit.googlecode.com/svn/documentation/2.0/user-signedoffby.html

You can send patches as follows:

  * To: mcgrof@kernel.org, adrian@freebsd.org
  * Cc: nic-devel@qualcomm.com
  * Subject: alx: foo

# BSD support

TBD
