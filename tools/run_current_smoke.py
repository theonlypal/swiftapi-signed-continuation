import argparse
import json
from pathlib import Path
import time
import runpod_smoke as driver
import prepare_smoke_bundle as bundle


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--bundle-out',type=Path,required=True)
    parser.add_argument('--wheel',type=Path,required=True)
    parser.add_argument('--service-wheel',type=Path,required=True)
    parser.add_argument('--predictions',type=Path,required=True)
    parser.add_argument('--predictions-sealed-at',required=True)
    parser.add_argument('--runpod-key-file',type=Path,required=True)
    parser.add_argument('--authorization',type=Path)
    parser.add_argument('--execute-one-approved-development-smoke',action='store_true',required=True)
    args=parser.parse_args()
    if not args.authorization and driver.DEFAULT_CLAIM.exists():
        raise FileExistsError('The single allocation authorization is consumed')
    if args.out.exists() or args.bundle_out.exists():
        raise FileExistsError('Output and bundle directories must be new')
    query={'include':'AVAILABILITY','product':'POD','cloud':'SECURE','count':1,'minCudaVersion':'12.8'}
    inventory_events=[]
    api=driver.RunPod(driver.key_from_existing(args.runpod_key_file),event_sink=inventory_events.append)
    inventory=api.call('GET','/catalog/gpus',params=query)
    snapshot={'queried_at_monotonic':time.monotonic(),'query':query,'body':inventory}
    choices=driver.qualifying_gpus(inventory)
    if not choices or choices[0]['price']['secure']>driver.MAX_COMPUTE_PER_HOUR:
        raise ValueError('No qualifying secure GPU within the bounded compute rate')
    selected=choices[0]
    centers=sorted(d['id'] for d in selected['dataCenters']
                   if d.get('availability') in ('LOW','MEDIUM','HIGH'))
    driver.GPU=bundle.GPU=selected['id']
    driver.DATA_CENTERS=bundle.DATA_CENTERS=centers[:1]
    bundle.build(args.bundle_out,args.wheel,args.service_wheel,
        predictions=args.predictions,predictions_sealed_at=args.predictions_sealed_at,
        author_confirmed_sealed=True)
    driver.save(args.bundle_out/'selection.json',{
        'selected':selected,'data_centers':centers[:1],
        'inventory_sha256':driver.sha(json.dumps(inventory,sort_keys=True).encode()),
        'queried_at':driver.now(),'allocation_requests':0,'provider_dispatches':inventory_events})
    options={'inventory_snapshot':snapshot,'api_connection':api}
    if args.authorization:options['authorization']=args.authorization
    return driver.run(args.bundle_out,args.out,args.runpod_key_file,**options)


if __name__=='__main__':raise SystemExit(main())
