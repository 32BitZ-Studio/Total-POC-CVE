from lib.core.module_parser import parser

paths = parser('./modules/hp-officejet-4630.yml','paths')
tags = parser('./modules/hp-officejet-4630.yml','tags')

print('{!} Atomic IoCs:',len(paths[0]))
for atomic_IoC_id in paths[0]:
    print('{!} IoC ID:',atomic_IoC_id,'Path:',paths[0][atomic_IoC_id],'Tag:',tags[0][atomic_IoC_id])

