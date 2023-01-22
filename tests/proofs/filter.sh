#! /bin/env sh

echo "#! /bin/env python3"
echo "from overflow import *"
echo ""
sed -n "/PROOF $1/,/CQFD $1/p"                                          |\
    sed '1d;$d'                                                         |\
    sed 's|	||'                                                         |\
    sed 's|//- ||'                                                      |\
    sed 's|^.*//-.*$||'                                                 |\
    sed 's|  *//.*||'                                                   |\
    sed 's|//|#|'                                                       |\
    sed 's|const ||'                                                    |\
    sed 's|;||'                                                         |\
    sed 's|ctx->|ctx_|'                                                 |\
    sed 's|\[|_|g'                                                      |\
    sed 's|\]||g'                                                       |\
    sed 's|(\([a-zA-Z0-9_]*\))\([a-zA-Z0-9_]*\)|\1(\2)|g'               |\
    sed 's|^\([a-zA-Z0-9_]*\) \([a-zA-Z0-9_]*\) = \(.*\)$|\2 = \1(\3)|' |\
    sed 's|\* \([0-9][0-9]*\)|\* cast(\1)|g'                            |\
    sed 's|\+ \([0-9][0-9]*\)|\+ cast(\1)|g'                            |\
    sed 's|\- \([0-9][0-9]*\)|\- cast(\1)|g'                            |\
    cat
