import ujson

if __name__ == '__main__':
    for line in open('joint_vt_chompy').readlines():
        js = ujson.loads(line)
        names = []
        for item in js:
            names.append(item['service_name'])
        print js[0]['object_id'], len(js), names
